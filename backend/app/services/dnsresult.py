"""DNS解析结果追踪：解析、结果数据集、批次合并、缓存与执行协同消费。

业务链路：

1. 读取域名与匹配的解析配置（含缓存 TTL、主备地址、配置版本、重试上限）；
2. 读取该域名的缓存快照，连同主解析/故障转移结果一起收拢成
   :class:`~app.services.dns_evidence.ResolutionEvidence`；
3. 由 :func:`~app.services.dns_evidence.decide_resolution` 单点裁决地址来源、
   服务器与故障转移路径，本服务只负责取数、加锁、落库；
4. 生成 DNS 解析结果数据集，结果绑定配置版本、使用服务器、故障转移路径、
   批次与证据摘要；完整性可随时校验；
5. 成功结果更新执行协同清单，失败结果把失败码/原因写回采集记录，
   执行协同只消费成功结果。

并发与幂等：

* 同一域名用独立 ``Lock`` 串行化，并发请求里后到者复用先到者刚写入缓存的结果，
  不会出现地址或地址来源分叉；
* 每个解析结果带确定性 ``幂等键``，重复处理同一份结果只返回既有记录，不重复计数；
* 缓存必须同时满足 TTL 未过期、配置版本一致、IPv6 优先级一致才可复用，
  过期缓存不会把旧配置版本的地址带回来。
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any

from app.services.dns_evidence import (
    FAILURE_CODES,
    PATH_NONE,
    SOURCE_CACHE,
    SOURCE_FAILOVER,
    SOURCE_NONE,
    SOURCE_PRIMARY,
    SOURCE_PRIMARY_IPV6,
    AttemptOutcome,
    CacheView,
    ResolutionDecision,
    ResolutionEvidence,
    cache_unusable_reason,
    decide_resolution,
)
from app.store import store

MODULE = "dnsresult"
CACHE_MODULE = "dnscache"
BATCH_MODULE = "dnsbatch"
EXEC_MODULE = "executioncoord"
CRAWL_MODULE = "crawlrecord"
CONFIG_MODULE = "dnsresolver"

RESULT_STATUSES = ["成功", "失败"]
RESULT_LIFECYCLE = ["生效", "已合并", "已失效", "失败"]
CONSUME_STATUSES = ["未消费", "已消费", "不可消费", "失效"]

TRACE_FIELDS = ["结果编号", "域名", "配置编号", "配置版本", "地址来源", "使用DNS服务器", "故障转移路径"]

# 同一域名的解析串行化；不同域名可以并行。写操作再用 _WRITE_LOCK 保护 id 分配与批量落库。
_DOMAIN_LOCKS: dict[str, threading.Lock] = {}
_DOMAIN_LOCKS_GUARD = threading.Lock()
_WRITE_LOCK = threading.RLock()

# 并发请求在锁上等待期间，若缓存已由先到请求写入，直接复用该结果。
_COALESCE_EPSILON_SECONDS = 0.001


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _now().isoformat(timespec="seconds")


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _next_id(rows: list[dict[str, Any]]) -> int:
    return max((_as_int(row.get("id"), 0) for row in rows), default=0) + 1


def _next_code(rows: list[dict[str, Any]], field: str, prefix: str) -> str:
    max_seq = 0
    for row in rows:
        text = str(row.get(field) or "")
        if text.startswith(prefix):
            max_seq = max(max_seq, _as_int(text[len(prefix):], 0))
    return f"{prefix}{max_seq + 1:04d}"


def normalize_domain(domain: str) -> str:
    value = str(domain or "").strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    value = value.split("/", 1)[0]
    if value.startswith("www."):
        value = value[4:]
    return value


def domain_matches(pattern: str, domain: str) -> bool:
    pattern = normalize_domain(pattern)
    if not pattern or not domain:
        return False
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return domain.endswith(suffix) and domain != suffix[1:]
    return False


class DnsresultService:
    # ------------------------------------------------------------------ 锁
    @staticmethod
    def _domain_lock(domain: str) -> threading.Lock:
        with _DOMAIN_LOCKS_GUARD:
            lock = _DOMAIN_LOCKS.get(domain)
            if lock is None:
                lock = threading.Lock()
                _DOMAIN_LOCKS[domain] = lock
            return lock

    # ------------------------------------------------------------------ 查询
    def list_entries(
        self,
        *,
        keyword: str | None = None,
        status: str | None = None,
        domain: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        rows = store.rows(MODULE)
        if keyword:
            rows = [
                row
                for row in rows
                if keyword in str(row.get("结果编号", "")) or keyword in str(row.get("域名", ""))
            ]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        if domain:
            wanted = normalize_domain(domain)
            rows = [row for row in rows if normalize_domain(str(row.get("域名", ""))) == wanted]
        total = len(rows)
        start = max(page - 1, 0) * size
        return rows[start:start + size], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        return store.find(MODULE, entry_id)

    def list_caches(self, domain: str | None = None) -> list[dict[str, Any]]:
        rows = store.rows(CACHE_MODULE)
        if domain:
            wanted = normalize_domain(domain)
            rows = [row for row in rows if normalize_domain(str(row.get("域名", ""))) == wanted]
        return rows

    def list_batches(self, domain: str | None = None) -> list[dict[str, Any]]:
        rows = store.rows(BATCH_MODULE)
        if domain:
            wanted = normalize_domain(domain)
            rows = [row for row in rows if normalize_domain(str(row.get("域名", ""))) == wanted]
        return rows

    def list_execution_manifest(self, domain: str | None = None) -> list[dict[str, Any]]:
        rows = store.rows(EXEC_MODULE)
        if domain:
            wanted = normalize_domain(domain)
            rows = [row for row in rows if normalize_domain(str(row.get("域名", ""))) == wanted]
        return rows

    def list_crawl_records(self, domain: str | None = None) -> list[dict[str, Any]]:
        rows = store.rows(CRAWL_MODULE)
        if domain:
            wanted = normalize_domain(domain)
            rows = [row for row in rows if normalize_domain(str(row.get("域名", ""))) == wanted]
        return rows

    def stats(self) -> dict[str, Any]:
        rows = store.rows(MODULE)
        caches = store.rows(CACHE_MODULE)
        manifest = store.rows(EXEC_MODULE)
        return {
            "结果总数": len(rows),
            "成功结果": sum(1 for row in rows if row.get("是否成功")),
            "失败结果": sum(1 for row in rows if row.get("status") == "失败"),
            "生效结果": sum(1 for row in rows if row.get("结果状态") == "生效"),
            "已合并结果": sum(1 for row in rows if row.get("结果状态") == "已合并"),
            "有效缓存": sum(1 for row in caches if row.get("是否有效")),
            "待消费清单": sum(1 for row in manifest if row.get("清单状态") == "待消费"),
            "已消费清单": sum(1 for row in manifest if row.get("清单状态") == "已消费"),
        }

    # ------------------------------------------------------------------ 配置
    def _find_config(self, domain: str, values: dict[str, Any]) -> dict[str, Any] | None:
        configs = store.rows(CONFIG_MODULE)
        requested_id = _as_int(values.get("配置ID"), 0)
        requested_code = str(values.get("配置编号") or "").strip()
        if requested_id or requested_code:
            for config in configs:
                if requested_id and _as_int(config.get("id")) == requested_id:
                    return config
                if requested_code and str(config.get("配置编号")) == requested_code:
                    return config
            return None
        candidates = [config for config in configs if domain_matches(str(config.get("域名模式", "")), domain)]
        if not candidates:
            return None
        candidates.sort(key=lambda item: (item.get("status") != "已启用", _as_int(item.get("id"))))
        return candidates[0]

    @staticmethod
    def _config_ipv6_preferred(config: dict[str, Any]) -> str:
        return str(config.get("IPv6优先") or "否").strip() or "否"

    @staticmethod
    def _failover_server(config: dict[str, Any]) -> str:
        explicit = str(config.get("故障转移DNS服务器") or "").strip()
        if explicit:
            return explicit
        return f"{config.get('DNS服务器') or '未配置'}(备用)"

    def _simulate_primary(self, config: dict[str, Any], overrides: dict[str, Any]) -> AttemptOutcome:
        state = str(overrides.get("主解析状态") or config.get("主解析状态") or "正常").strip()
        address = str(config.get("主解析地址") or "").strip() or None
        if state == "超时":
            return AttemptOutcome(ok=False, address=address, timeout=True, detail="主解析超时")
        if state in {"失败", "不可用"}:
            return AttemptOutcome(ok=False, address=address, timeout=False, detail="主解析失败")
        if not address:
            return AttemptOutcome(ok=False, address=None, timeout=False, detail="主解析无可用地址")
        return AttemptOutcome(ok=True, address=address)

    def _simulate_failover(self, config: dict[str, Any], overrides: dict[str, Any]) -> AttemptOutcome:
        state = str(overrides.get("故障转移状态") or config.get("故障转移状态") or "正常").strip()
        address = str(config.get("故障转移地址") or "").strip() or None
        if state == "超时":
            return AttemptOutcome(ok=False, address=address, timeout=True, detail="故障转移超时")
        if state in {"失败", "不可用"}:
            return AttemptOutcome(ok=False, address=address, timeout=False, detail="故障转移失败")
        if not address:
            return AttemptOutcome(ok=False, address=None, timeout=False, detail="未配置故障转移地址")
        return AttemptOutcome(ok=True, address=address)

    # ------------------------------------------------------------------ 缓存
    def _cache_row(self, domain: str) -> dict[str, Any] | None:
        match = None
        for row in store.rows(CACHE_MODULE):
            if normalize_domain(str(row.get("域名", ""))) == domain:
                match = row
        return match

    def _cache_view(self, domain: str, config: dict[str, Any] | None, now_ts: float) -> tuple[CacheView, dict[str, Any] | None]:
        row = self._cache_row(domain)
        if row is None:
            return CacheView(present=False), None
        expires = float(row.get("过期时间戳") or 0.0)
        remaining = max(int(expires - now_ts), 0)
        invalid_reason = str(row.get("失效原因") or "")
        if not bool(row.get("是否有效", True)) and not invalid_reason:
            invalid_reason = "缓存已标记失效"
        view = CacheView(
            present=True,
            record_id=_as_int(row.get("id")),
            address=str(row.get("解析地址") or ""),
            source=str(row.get("地址来源") or SOURCE_NONE),
            server=str(row.get("使用DNS服务器") or ""),
            config_version=_as_int(row.get("配置版本"), -1),
            ipv6_preferred=str(row.get("IPv6优先") or ""),
            batch_id=str(row.get("批次号") or ""),
            batch_version=_as_int(row.get("批次版本"), 0),
            remaining_ttl=remaining,
            result_code=str(row.get("来源结果编号") or ""),
            invalid_reason=invalid_reason,
        )
        return view, row

    def _write_cache(
        self,
        *,
        domain: str,
        config: dict[str, Any],
        decision: ResolutionDecision,
        batch_id: str,
        batch_version: int,
        result_code: str,
        ttl_seconds: int,
        now_ts: float,
    ) -> dict[str, Any]:
        row = self._cache_row(domain)
        if row is None:
            row = {"id": _next_id(store.rows(CACHE_MODULE)), "域名": domain}
            store.rows(CACHE_MODULE).append(row)
        expires = now_ts + max(ttl_seconds, 0)
        row.update(
            {
                "配置编号": config.get("配置编号"),
                "配置ID": _as_int(config.get("id"), 0),
                "配置版本": _as_int(config.get("配置版本"), 0),
                "解析地址": decision.address,
                "地址来源": decision.source,
                "使用DNS服务器": decision.server,
                "故障转移路径": decision.failover_path,
                "IPv6优先": self._config_ipv6_preferred(config),
                "批次号": batch_id,
                "批次版本": batch_version,
                "写入时间": datetime.fromtimestamp(now_ts, tz=timezone.utc).isoformat(timespec="seconds"),
                "写入时间戳": now_ts,
                "过期时间": datetime.fromtimestamp(expires, tz=timezone.utc).isoformat(timespec="seconds"),
                "过期时间戳": expires,
                "来源结果编号": result_code,
                "是否有效": True,
                "失效原因": "",
            }
        )
        return row

    def _invalidate_cache(self, domain: str, reason: str) -> None:
        row = self._cache_row(domain)
        if row is None:
            return
        row["是否有效"] = False
        row["失效原因"] = reason

    def invalidate_domain_caches(self, pattern: str, reason: str = "CONFIG_VERSION_MISMATCH") -> int:
        """配置发布新版本后，按域名模式失效所有相关缓存，返回失效条数。

        域名模式可能是通配符（``*.example.com``），因此逐个域名匹配而不是字符串相等。
        """
        count = 0
        for row in store.rows(CACHE_MODULE):
            domain = normalize_domain(str(row.get("域名", "")))
            if not domain_matches(pattern, domain):
                continue
            row["是否有效"] = False
            row["失效原因"] = reason
            count += 1
        return count

    # ------------------------------------------------------------------ 批次
    def _new_batch(
        self,
        *,
        domain: str,
        config: dict[str, Any],
        merge_previous: bool,
    ) -> tuple[str, int, list[str]]:
        """为一次新解析分配批次；同域名的旧生效批次合并到新批次，避免两个版本并存。"""
        rows = store.rows(BATCH_MODULE)
        # 同域名 + 同配置的旧生效批次（无论哪个配置版本）一并合并到新批次，
        # 保证「两个批次版本不得并存」。
        same = [
            row
            for row in rows
            if normalize_domain(str(row.get("域名", ""))) == domain
            and _as_int(row.get("配置ID"), 0) == _as_int(config.get("id"), 0)
        ]
        next_version = max((_as_int(row.get("批次版本"), 0) for row in same), default=0) + 1
        batch_id = f"DNB-{config.get('配置编号') or 'UNKNOWN'}-{next_version:03d}"
        merged: list[str] = []
        if merge_previous:
            for row in same:
                if row.get("状态") == "生效" and row.get("批次编号") != batch_id:
                    row["状态"] = "已合并"
                    row["合并到"] = batch_id
                    merged.append(str(row.get("批次编号")))
        rows.append(
            {
                "id": _next_id(rows),
                "批次编号": batch_id,
                "域名": domain,
                "配置ID": _as_int(config.get("id"), 0),
                "配置编号": config.get("配置编号"),
                "配置版本": _as_int(config.get("配置版本"), 0),
                "批次版本": next_version,
                "状态": "生效",
                "创建时间": _now_iso(),
                "合并到": None,
            }
        )
        if merged:
            self._mark_results_merged(domain, merged, batch_id)
        return batch_id, next_version, merged

    def _mark_results_merged(self, domain: str, batch_ids: list[str], target_batch: str) -> None:
        """旧批次整体并入新批次：旧结果保留作证据，但不再作为可消费/生效结果。"""
        for row in store.rows(MODULE):
            if row.get("批次号") not in batch_ids:
                continue
            if normalize_domain(str(row.get("域名", ""))) != domain:
                continue
            if not row.get("是否成功"):
                continue
            row["结果状态"] = "已合并"
            row["合并到"] = target_batch
            row["消费状态"] = "失效"
            # 旧结果对应的清单不再可消费，避免执行协同拿到已过期地址。
            for manifest in store.rows(EXEC_MODULE):
                if manifest.get("结果编号") != row.get("结果编号"):
                    continue
                if manifest.get("清单状态") == "待消费":
                    manifest["清单状态"] = "已失效"
                    manifest["pending"] = False
                    manifest["备注"] = f"批次已合并到 {target_batch}，清单失效"

    # ------------------------------------------------------------------ 采集记录
    def _write_crawl_record(
        self,
        *,
        domain: str,
        job_code: str,
        crawl_url: str,
        decision: ResolutionDecision,
        result_code: str,
    ) -> str:
        """把解析结果写回采集记录；失败时保留失败码与可读原因。"""
        rows = store.rows(CRAWL_MODULE)
        target = None
        if job_code:
            for row in rows:
                if row.get("作业编号") == job_code and normalize_domain(str(row.get("域名", ""))) == domain:
                    target = row
                    break
            if target is None:
                for row in rows:
                    if row.get("作业编号") == job_code:
                        target = row
                        break
        if target is None:
            for row in rows:
                if normalize_domain(str(row.get("域名", ""))) == domain:
                    target = row
                    break
        if target is None:
            target = {
                "id": _next_id(rows),
                "记录编号": _next_code(rows, "记录编号", "CREC-"),
                "作业编号": job_code,
                "域名": domain,
                "采集URL": crawl_url or f"https://{domain}/",
                "解析结果编号": "",
                "解析状态": "待解析",
                "解析地址": "",
                "失败码": "",
                "失败原因": "",
                "重试次数": 0,
                "更新时间": _now_iso(),
            }
            rows.append(target)

        target["解析结果编号"] = result_code
        target["重试次数"] = decision.retry_count
        target["更新时间"] = _now_iso()
        if decision.ok:
            target["status"] = "成功"
            target["pending"] = False
            target["abnormal"] = False
            target["解析状态"] = "成功"
            target["解析地址"] = decision.address
            target["失败码"] = ""
            target["失败原因"] = ""
            target["使用DNS服务器"] = decision.server
            target["故障转移路径"] = decision.failover_path
        else:
            target["status"] = "解析失败"
            target["pending"] = decision.failure_code != "RETRY_EXHAUSTED"
            target["abnormal"] = decision.failure_code == "RETRY_EXHAUSTED"
            target["解析状态"] = "失败"
            target["解析地址"] = ""
            target["失败码"] = decision.failure_code
            target["失败原因"] = decision.failure_reason
        return str(target["记录编号"])

    # ------------------------------------------------------------------ 执行协同
    def _update_execution_manifest(
        self,
        *,
        domain: str,
        config: dict[str, Any] | None,
        decision: ResolutionDecision,
        result_code: str,
        crawl_record_code: str,
    ) -> str:
        """成功结果写入执行协同清单；失败结果不进入可消费清单。

        清单按「域名 + 配置版本」维护：新版本使用新清单，旧版本清单标记为已失效；
        这样同一份 DNS 解析结果反复处理不会重复生成清单，也不会让执行协同
        拿到旧版本的地址。
        """
        rows = store.rows(EXEC_MODULE)
        version = _as_int(config.get("配置版本"), 0) if config else 0
        target = None
        for row in rows:
            if (
                normalize_domain(str(row.get("域名", ""))) == domain
                and _as_int(row.get("配置版本"), 0) == version
            ):
                target = row
        if not decision.ok:
            if target is not None and target.get("清单状态") == "待消费":
                target["清单状态"] = "不可消费"
                target["备注"] = f"解析失败：{decision.failure_code}"
            return str(target.get("清单编号") or "") if target else ""
        # 旧版本清单不再是可消费目标。
        for row in rows:
            if (
                normalize_domain(str(row.get("域名", ""))) == domain
                and row.get("清单状态") == "待消费"
                and _as_int(row.get("配置版本"), 0) != version
            ):
                row["清单状态"] = "已失效"
                row["pending"] = False
                row["备注"] = f"配置已切换到 v{version}，旧清单失效"
        if target is None:
            target = {
                "id": _next_id(rows),
                "清单编号": _next_code(rows, "清单编号", "EXEC-"),
                "域名": domain,
            }
            rows.append(target)
        target.update(
            {
                "status": "待消费",
                "pending": True,
                "abnormal": False,
                "结果编号": result_code,
                "解析地址": decision.address,
                "地址来源": decision.source,
                "配置编号": config.get("配置编号") if config else "",
                "配置版本": version,
                "使用DNS服务器": decision.server,
                "故障转移路径": decision.failover_path,
                "采集记录编号": crawl_record_code,
                "清单状态": "待消费",
                "消费时间": "",
                "备注": "仅消费成功的DNS解析结果",
            }
        )
        return str(target["清单编号"])

    # ------------------------------------------------------------------ 幂等键
    @staticmethod
    def _idempotency_key(
        *,
        domain: str,
        config: dict[str, Any] | None,
        evidence: ResolutionEvidence,
        decision: ResolutionDecision,
        refresh: bool,
    ) -> str:
        """幂等键只包含「同一份解析结果」的稳定内容。

        不含地址来源：TTL 内重复请求即使这次由缓存给出答案，也属于同一份结果，
        不再重复计数；批次边界冲突会改变裁决，因此显式纳入键。
        """
        return "|".join(
            [
                domain,
                str(config.get("配置编号") if config else ""),
                str(evidence.config_version_now if evidence.config_version_now is not None else ""),
                evidence.ipv6_preferred,
                str(evidence.attempts),
                "refresh" if refresh else "normal",
                evidence.primary.failure_kind,
                evidence.failover.failure_kind,
                decision.address or "",
                "conflict" if decision.conflict else "",
                decision.failure_code,
            ]
        )

    @staticmethod
    def _find_by_key(key: str) -> dict[str, Any] | None:
        for row in store.rows(MODULE):
            if row.get("幂等键") == key:
                return row
        return None

    # ------------------------------------------------------------------ 解析
    def resolve(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """解析一个域名并生成结果。返回 (结果记录, 说明)。"""
        raw_domain = str(values.get("域名") or values.get("domain") or "").strip()
        domain = normalize_domain(raw_domain)
        if not domain:
            return None, "缺少域名，无法执行DNS解析"
        refresh = bool(values.get("刷新") or values.get("refresh") or False)
        job_code = str(values.get("作业编号") or "").strip()
        crawl_url = str(values.get("采集URL") or "").strip()
        overrides = {
            "主解析状态": values.get("主解析状态"),
            "故障转移状态": values.get("故障转移状态"),
        }

        started_ts = time.time()
        lock = self._domain_lock(domain)
        with lock:
            result, message = self._resolve_locked(
                domain=domain,
                values=values,
                refresh=refresh,
                job_code=job_code,
                crawl_url=crawl_url,
                overrides=overrides,
                started_ts=started_ts,
            )
        # 返回副本：路由层或调用方改动响应字段不会污染内存仓库，
        # 数据集完整性只由服务自身的写入路径改变。
        return (dict(result) if result is not None else None), message

    def _resolve_locked(
        self,
        *,
        domain: str,
        values: dict[str, Any],
        refresh: bool,
        job_code: str,
        crawl_url: str,
        overrides: dict[str, Any],
        started_ts: float,
    ) -> tuple[dict[str, Any] | None, str]:
        now_ts = time.time()
        config = self._find_config(domain, values)
        with _WRITE_LOCK:
            cache_view, cache_row = self._cache_view(domain, config, now_ts)

            # 同一份解析结果重复处理：缓存仍可复用（TTL/版本/IPv6 一致）时只算一次，
            # 直接返回既有记录，不重复计数；缓存过期或版本失效则正常重新解析。
            if config is not None and not refresh and cache_view.present and cache_view.result_code:
                reusable = cache_unusable_reason(
                    self._evidence(domain, config, values, cache_view, overrides, 1, now_ts)
                ) == ""
                if reusable:
                    existing = self._result_by_code(cache_view.result_code)
                    if existing is not None and existing.get("是否成功"):
                        return existing, f"幂等复用：结果 {existing.get('结果编号')} 已存在，本次不重复计数"

            # 并发单飞：等待域名锁期间先到请求已写入缓存，直接复用它的结果，避免分叉。
            # 只认「本次请求开始之后」写入且版本、优先级一致的缓存，旧记录不在此列。
            if (
                refresh
                and config is not None
                and cache_view.present
                and cache_view.result_code
                and float((cache_row or {}).get("写入时间戳") or 0.0) >= started_ts - _COALESCE_EPSILON_SECONDS
            ):
                existing = self._result_by_code(cache_view.result_code)
                coalescable = cache_unusable_reason(
                    self._evidence(domain, config, values, cache_view, overrides, 1, now_ts)
                ) == ""
                if existing is not None and existing.get("是否成功") and coalescable:
                    return existing, f"并发解析已合并：复用结果 {existing.get('结果编号')}"

            if config is None:
                return self._record_failure(
                    domain=domain,
                    config=None,
                    values=values,
                    overrides=overrides,
                    failure_code="CONFIG_NOT_FOUND",
                    failure_reason=FAILURE_CODES["CONFIG_NOT_FOUND"],
                    attempts=1,
                    cache_view=cache_view,
                    job_code=job_code,
                    crawl_url=crawl_url,
                    now_ts=now_ts,
                )

            version_at_start = _as_int(
                values.get("配置版本快照"), _as_int(config.get("配置版本"), 0)
            )
            retry_limit = max(_as_int(config.get("重试上限"), 3), 1)
            attempts = self._resolve_attempts(values)
            primary = self._simulate_primary(config, overrides)
            failover = self._simulate_failover(config, overrides)

            # 配置可能在解析过程中被切换：落库前重新读取版本号。
            version_now = _as_int(config.get("配置版本"), 0)
            primary_attempted = self._is_primary_attempted(config, overrides, refresh)

            evidence = self._evidence(
                domain, config, values, cache_view, overrides, attempts, now_ts,
                primary=primary,
                failover=failover,
                version_at_start=version_at_start,
                version_now=version_now,
                retry_limit=retry_limit,
                refresh=refresh,
                primary_attempted=primary_attempted,
            )
            decision = decide_resolution(evidence)

            # 缓存失效时留下可追溯原因，避免静默沿用旧版本/旧 IPv6 优先级的地址。
            if cache_view.present and not decision.ok:
                reason = cache_unusable_reason(evidence)
                if reason not in {"", "无缓存"} and reason in FAILURE_CODES:
                    self._invalidate_cache(domain, reason)

            key = self._idempotency_key(
                domain=domain, config=config, evidence=evidence, decision=decision, refresh=refresh
            )
            existing = self._find_by_key(key)
            if existing is not None:
                return existing, f"幂等复用：结果 {existing.get('结果编号')} 已存在，本次不重复计数"

            if not decision.ok:
                return self._record_failure(
                    domain=domain,
                    config=config,
                    values=values,
                    overrides=overrides,
                    failure_code=decision.failure_code,
                    failure_reason=decision.failure_reason,
                    attempts=attempts,
                    cache_view=cache_view,
                    job_code=job_code,
                    crawl_url=crawl_url,
                    now_ts=now_ts,
                    decision=decision,
                    evidence=evidence,
                    idempotency_key=key,
                )

            return self._record_success(
                domain=domain,
                config=config,
                decision=decision,
                evidence=evidence,
                cache_view=cache_view,
                key=key,
                job_code=job_code,
                crawl_url=crawl_url,
                now_ts=now_ts,
                attempts=attempts,
            )

    @staticmethod
    def _is_primary_attempted(
        config: dict[str, Any] | None,
        overrides: dict[str, Any],
        refresh: bool,
    ) -> bool:
        """本次请求是否真实探测了主解析：强制刷新、显式指定状态或配置本身异常。"""
        if refresh:
            return True
        if str(overrides.get("主解析状态") or "").strip():
            return True
        if config is None:
            return False
        return str(config.get("主解析状态") or "正常").strip() not in {"", "正常"}

    def _evidence(
        self,
        domain: str,
        config: dict[str, Any] | None,
        values: dict[str, Any],
        cache_view: CacheView,
        overrides: dict[str, Any],
        attempts: int,
        now_ts: float,
        *,
        primary: AttemptOutcome | None = None,
        failover: AttemptOutcome | None = None,
        version_at_start: int | None = None,
        version_now: int | None = None,
        retry_limit: int | None = None,
        refresh: bool = False,
        primary_attempted: bool | None = None,
    ) -> ResolutionEvidence:
        if config is None:
            return ResolutionEvidence(
                domain=domain,
                config_id=None,
                config_code="",
                config_status="",
                config_version_at_start=version_at_start,
                config_version_now=version_now,
                ipv6_preferred="否",
                ipv6_address="",
                primary_address="",
                failover_address="",
                primary_server="",
                failover_server="",
                timeout_ms=0,
                ttl_seconds=0,
                retry_limit=retry_limit or 1,
                attempts=attempts,
                primary=primary or AttemptOutcome(ok=False),
                failover=failover or AttemptOutcome(ok=False),
                cache=cache_view,
                refresh=refresh,
                primary_attempted=(
                    self._is_primary_attempted(config, overrides, refresh)
                    if primary_attempted is None
                    else primary_attempted
                ),
            )
        return ResolutionEvidence(
            domain=domain,
            config_id=_as_int(config.get("id"), 0),
            config_code=str(config.get("配置编号") or ""),
            config_status=str(config.get("status") or ""),
            config_version_at_start=version_at_start if version_at_start is not None else _as_int(config.get("配置版本"), 0),
            config_version_now=version_now if version_now is not None else _as_int(config.get("配置版本"), 0),
            ipv6_preferred=self._config_ipv6_preferred(config),
            ipv6_address=str(config.get("IPv6地址") or ""),
            primary_address=str(config.get("主解析地址") or ""),
            failover_address=str(config.get("故障转移地址") or ""),
            primary_server=str(config.get("DNS服务器") or ""),
            failover_server=self._failover_server(config),
            timeout_ms=_as_int(config.get("解析超时毫秒"), 0),
            ttl_seconds=_as_int(config.get("缓存TTL秒"), 0),
            retry_limit=retry_limit or max(_as_int(config.get("重试上限"), 3), 1),
            attempts=attempts,
            primary=primary or self._simulate_primary(config, overrides),
            failover=failover or self._simulate_failover(config, overrides),
            cache=cache_view,
            refresh=refresh,
            primary_attempted=(
                self._is_primary_attempted(config, overrides, refresh)
                if primary_attempted is None
                else primary_attempted
            ),
        )

    @staticmethod
    def _resolve_attempts(values: dict[str, Any]) -> int:
        """尝试次数只由请求显式给出，默认 1，保证同一请求的幂等键稳定。"""
        return max(_as_int(values.get("尝试次数"), 1), 1)

    # ------------------------------------------------------------------ 落库
    def _record_success(
        self,
        *,
        domain: str,
        config: dict[str, Any],
        decision: ResolutionDecision,
        evidence: ResolutionEvidence,
        cache_view: CacheView,
        key: str,
        job_code: str,
        crawl_url: str,
        now_ts: float,
        attempts: int,
    ) -> tuple[dict[str, Any], str]:
        rows = store.rows(MODULE)
        cache_hit = decision.source == SOURCE_CACHE
        if cache_hit and cache_view.batch_id:
            batch_id = cache_view.batch_id
            batch_version = cache_view.batch_version
            merged: list[str] = []
        else:
            batch_id, batch_version, merged = self._new_batch(
                domain=domain, config=config, merge_previous=True
            )

        code = _next_code(rows, "结果编号", "DNSRES-")
        result: dict[str, Any] = {
            "id": _next_id(rows),
            "status": "成功",
            "pending": False,
            "abnormal": False,
            "结果编号": code,
            "域名": domain,
            "配置编号": config.get("配置编号"),
            "配置ID": _as_int(config.get("id"), 0),
            "配置版本": _as_int(config.get("配置版本"), 0),
            "解析地址": decision.address,
            "地址来源": decision.source,
            "使用DNS服务器": decision.server,
            "故障转移路径": decision.failover_path,
            "缓存TTL秒": evidence.ttl_seconds,
            "剩余TTL秒": evidence.ttl_seconds if not cache_hit else cache_view.remaining_ttl,
            "批次号": batch_id,
            "批次版本": batch_version,
            "来源批次号": cache_view.batch_id if cache_hit else "",
            "是否成功": True,
            "失败码": "",
            "失败原因": "",
            "重试次数": decision.retry_count,
            "尝试次数": attempts,
            "作业编号": job_code,
            "证据摘要": self._evidence_summary(evidence, decision, merged),
            "幂等键": key,
            "结果状态": "生效",
            "合并到": None,
            "消费状态": "未消费",
            "采集记录编号": "",
            "创建时间": _now_iso(),
            "是否刷新": evidence.refresh,
            "冲突裁决": decision.conflict,
            "决策摘要": decision.summary(),
        }
        rows.append(result)

        if not cache_hit:
            self._write_cache(
                domain=domain,
                config=config,
                decision=decision,
                batch_id=batch_id,
                batch_version=batch_version,
                result_code=code,
                ttl_seconds=evidence.ttl_seconds,
                now_ts=now_ts,
            )
        crawl_code = self._write_crawl_record(
            domain=domain,
            job_code=job_code,
            crawl_url=crawl_url,
            decision=decision,
            result_code=code,
        )
        result["采集记录编号"] = crawl_code
        manifest_code = self._update_execution_manifest(
            domain=domain,
            config=config,
            decision=decision,
            result_code=code,
            crawl_record_code=crawl_code,
        )
        result["执行清单编号"] = manifest_code
        message = f"DNS解析成功：{decision.address}（{decision.source}）"
        if decision.conflict:
            message += "；批次边界冲突已裁决为缓存优先"
        if merged:
            message += "；已合并旧批次：" + "、".join(merged)
        return result, message

    def _record_failure(
        self,
        *,
        domain: str,
        config: dict[str, Any] | None,
        values: dict[str, Any],
        overrides: dict[str, Any],
        failure_code: str,
        failure_reason: str,
        attempts: int,
        cache_view: CacheView,
        job_code: str,
        crawl_url: str,
        now_ts: float,
        decision: ResolutionDecision | None = None,
        evidence: ResolutionEvidence | None = None,
        idempotency_key: str = "",
    ) -> tuple[dict[str, Any], str]:
        rows = store.rows(MODULE)
        if decision is None:
            retry_limit = max(_as_int((config or {}).get("重试上限"), 3), 1)
            evidence = evidence or self._evidence(
                domain,
                config,
                values,
                cache_view,
                overrides,
                attempts,
                now_ts,
                version_at_start=_as_int((config or {}).get("配置版本"), 0),
                version_now=_as_int((config or {}).get("配置版本"), 0),
                retry_limit=retry_limit,
            )
            decision = ResolutionDecision(
                ok=False,
                address="",
                source=SOURCE_NONE,
                failover_path=PATH_NONE,
                server=str((config or {}).get("DNS服务器") or ""),
                failure_code=failure_code,
                failure_reason=failure_reason,
                retry_count=max(attempts - 1, 0),
                cache_status="未使用",
            )
        if not idempotency_key:
            idempotency_key = self._idempotency_key(
                domain=domain, config=config, evidence=evidence, decision=decision, refresh=False
            )
        existing = self._find_by_key(idempotency_key)
        if existing is not None:
            return existing, f"幂等复用：失败结果 {existing.get('结果编号')} 已存在，本次不重复计数"

        code = _next_code(rows, "结果编号", "DNSRES-")
        result: dict[str, Any] = {
            "id": _next_id(rows),
            "status": "失败",
            "pending": failure_code != "RETRY_EXHAUSTED",
            "abnormal": failure_code == "RETRY_EXHAUSTED",
            "结果编号": code,
            "域名": domain,
            "配置编号": config.get("配置编号") if config else "",
            "配置ID": _as_int(config.get("id"), 0) if config else 0,
            "配置版本": _as_int(config.get("配置版本"), 0) if config else 0,
            "解析地址": "",
            "地址来源": decision.source,
            "使用DNS服务器": decision.server,
            "故障转移路径": decision.failover_path,
            "缓存TTL秒": _as_int((config or {}).get("缓存TTL秒"), 0),
            "剩余TTL秒": cache_view.remaining_ttl,
            "批次号": cache_view.batch_id,
            "批次版本": cache_view.batch_version,
            "来源批次号": "",
            "是否成功": False,
            "失败码": failure_code,
            "失败原因": failure_reason,
            "重试次数": decision.retry_count,
            "尝试次数": attempts,
            "作业编号": job_code,
            "证据摘要": self._evidence_summary(evidence, decision, []),
            "幂等键": idempotency_key,
            "结果状态": "失败",
            "合并到": None,
            "消费状态": "不可消费",
            "采集记录编号": "",
            "创建时间": _now_iso(),
            "是否刷新": evidence.refresh if evidence else False,
            "冲突裁决": decision.conflict,
            "决策摘要": decision.summary(),
        }
        rows.append(result)
        crawl_code = self._write_crawl_record(
            domain=domain,
            job_code=job_code,
            crawl_url=crawl_url,
            decision=decision,
            result_code=code,
        )
        result["采集记录编号"] = crawl_code
        # 失败结果只写回采集记录，不进入执行协同可消费清单。
        manifest_code = self._update_execution_manifest(
            domain=domain,
            config=config,
            decision=decision,
            result_code=code,
            crawl_record_code=crawl_code,
        )
        result["执行清单编号"] = manifest_code
        return result, f"DNS解析失败：{failure_code}，{failure_reason}"

    @staticmethod
    def _evidence_summary(
        evidence: ResolutionEvidence | None,
        decision: ResolutionDecision,
        merged: list[str],
    ) -> dict[str, Any]:
        if evidence is None:
            return {"决策": decision.summary(), "已合并批次": merged}
        summary = evidence.base()
        summary["决策"] = decision.summary()
        summary["已合并批次"] = merged
        if decision.conflict:
            summary["批次边界冲突"] = decision.conflict
        return summary

    def _result_by_code(self, code: str) -> dict[str, Any] | None:
        for row in store.rows(MODULE):
            if row.get("结果编号") == code:
                return row
        return None

    # ------------------------------------------------------------------ 执行协同消费
    def consume_ready(self) -> dict[str, Any]:
        """执行协同侧只消费成功的DNS解析结果；失败结果把原因写回采集记录。"""
        with _WRITE_LOCK:
            consumed: list[dict[str, Any]] = []
            blocked: list[dict[str, Any]] = []
            skipped: list[dict[str, Any]] = []
            for manifest in store.rows(EXEC_MODULE):
                if manifest.get("清单状态") != "待消费":
                    continue
                result = self._result_by_code(str(manifest.get("结果编号") or ""))
                if result is None:
                    skipped.append({"清单编号": manifest.get("清单编号"), "原因": "结果已不存在"})
                    continue
                if not result.get("是否成功"):
                    manifest["清单状态"] = "不可消费"
                    manifest["abnormal"] = True
                    manifest["备注"] = f"解析失败：{result.get('失败码')}，{result.get('失败原因')}"
                    result["消费状态"] = "不可消费"
                    blocked.append(manifest)
                    continue
                manifest["status"] = "已消费"
                manifest["pending"] = False
                manifest["清单状态"] = "已消费"
                manifest["消费时间"] = _now_iso()
                manifest["解析地址"] = result.get("解析地址")
                manifest["地址来源"] = result.get("地址来源")
                manifest["使用DNS服务器"] = result.get("使用DNS服务器")
                manifest["故障转移路径"] = result.get("故障转移路径")
                result["消费状态"] = "已消费"
                for record in store.rows(CRAWL_MODULE):
                    if record.get("记录编号") == result.get("采集记录编号"):
                        record["消费状态"] = "已消费"
                        record["更新时间"] = _now_iso()
                consumed.append(manifest)
            return {
                "consumed": len(consumed),
                "blocked": len(blocked),
                "skipped": skipped,
                "items": consumed,
                "blocked_items": blocked,
            }

    # ------------------------------------------------------------------ 完整性校验
    def verify(self, entry_id: int | None = None) -> dict[str, Any]:
        """校验DNS解析结果数据集的完整性：字段、批次、缓存、证据与消费链路。"""
        rows = store.rows(MODULE)
        issues: list[dict[str, Any]] = []
        targets = rows
        if entry_id is not None:
            entry = store.find(MODULE, entry_id)
            if entry is None:
                return {"ok": False, "checked": 0, "issues": [{"对象": str(entry_id), "问题": "结果不存在"}]}
            targets = [entry]

        codes: dict[str, dict[str, Any]] = {
            str(row.get("结果编号")): row for row in rows if row.get("结果编号")
        }
        batch_ids = {str(row.get("批次编号")): row for row in store.rows(BATCH_MODULE) if row.get("批次编号")}
        configs = {_as_int(row.get("id")): row for row in store.rows(CONFIG_MODULE)}
        manifest_result_codes = {str(row.get("结果编号")) for row in store.rows(EXEC_MODULE)}

        for row in targets:
            code = str(row.get("结果编号") or "<无编号>")
            # CONFIG_NOT_FOUND 是「没有配置可用于追踪」的明确失败，不要求绑定配置字段；
            # 其余结果（含 CONFIG_DISABLED）必须能追溯到配置版本与服务器。
            config_trace_required = row.get("失败码") != "CONFIG_NOT_FOUND"
            for field in TRACE_FIELDS:
                if field in {"配置编号", "配置版本", "使用DNS服务器"} and not config_trace_required:
                    continue
                if not str(row.get(field) or "").strip():
                    issues.append({"结果编号": code, "字段": field, "问题": "追溯字段缺失"})
            if not str(row.get("幂等键") or "").strip():
                issues.append({"结果编号": code, "字段": "幂等键", "问题": "缺少幂等键，无法保证只处理一次"})
            if not isinstance(row.get("证据摘要"), dict) or not row.get("证据摘要"):
                issues.append({"结果编号": code, "字段": "证据摘要", "问题": "缺少证据摘要"})

            if row.get("是否成功"):
                if not str(row.get("解析地址") or "").strip():
                    issues.append({"结果编号": code, "字段": "解析地址", "问题": "成功结果缺少解析地址"})
                if row.get("地址来源") not in {
                    SOURCE_PRIMARY,
                    SOURCE_PRIMARY_IPV6,
                    SOURCE_FAILOVER,
                    SOURCE_CACHE,
                }:
                    issues.append({"结果编号": code, "字段": "地址来源", "问题": "地址来源不在允许取值内"})
                if row.get("地址来源") == SOURCE_FAILOVER and not str(row.get("故障转移路径") or "").startswith("主解析"):
                    issues.append(
                        {"结果编号": code, "字段": "故障转移路径", "问题": "故障转移结果缺少主备切换路径"}
                    )
                if not str(row.get("批次号") or "").strip():
                    issues.append({"结果编号": code, "字段": "批次号", "问题": "成功结果缺少批次号"})
                elif row.get("批次号") not in batch_ids:
                    issues.append({"结果编号": code, "字段": "批次号", "问题": "批次号未登记"})
                else:
                    batch = batch_ids[str(row.get("批次号"))]
                    if _as_int(batch.get("配置版本"), 0) != _as_int(row.get("配置版本"), 0):
                        issues.append(
                            {"结果编号": code, "字段": "批次号", "问题": "批次配置版本与结果不一致"}
                        )
                if row.get("结果状态") == "已合并" and not str(row.get("合并到") or "").strip():
                    issues.append({"结果编号": code, "字段": "合并到", "问题": "已合并结果缺少目标批次"})
            else:
                if not str(row.get("失败码") or "").strip():
                    issues.append({"结果编号": code, "字段": "失败码", "问题": "失败结果缺少失败码"})
                elif row.get("失败码") not in FAILURE_CODES:
                    issues.append({"结果编号": code, "字段": "失败码", "问题": "失败码不在登记范围内"})
                if not str(row.get("失败原因") or "").strip():
                    issues.append({"结果编号": code, "字段": "失败原因", "问题": "失败结果缺少原因"})
                if str(row.get("解析地址") or "").strip():
                    issues.append({"结果编号": code, "字段": "解析地址", "问题": "失败结果不应带解析地址"})

            config_id = _as_int(row.get("配置ID"), 0)
            if config_id and config_id in configs:
                config = configs[config_id]
                if _as_int(row.get("配置版本"), 0) > _as_int(config.get("配置版本"), 0):
                    issues.append(
                        {"结果编号": code, "字段": "配置版本", "问题": "结果配置版本超前于当前配置"}
                    )
                if row.get("结果状态") == "生效" and row.get("是否成功"):
                    if _as_int(row.get("配置版本"), 0) != _as_int(config.get("配置版本"), 0):
                        issues.append(
                            {"结果编号": code, "字段": "配置版本", "问题": "生效结果仍引用旧配置版本"}
                        )
            elif config_id:
                issues.append({"结果编号": code, "字段": "配置ID", "问题": "解析配置不存在"})

            evidence = row.get("证据摘要") if isinstance(row.get("证据摘要"), dict) else {}
            decision = evidence.get("决策") if isinstance(evidence.get("决策"), dict) else {}
            if decision:
                if decision.get("地址") != row.get("解析地址"):
                    issues.append(
                        {"结果编号": code, "字段": "证据摘要.决策.地址", "问题": "证据地址与结果地址不一致"}
                    )
                if decision.get("地址来源") != row.get("地址来源"):
                    issues.append(
                        {"结果编号": code, "字段": "证据摘要.决策.地址来源", "问题": "证据来源与结果来源不一致"}
                    )
                if decision.get("故障转移路径") != row.get("故障转移路径"):
                    issues.append(
                        {"结果编号": code, "字段": "证据摘要.决策.故障转移路径", "问题": "证据路径与结果路径不一致"}
                    )
                if decision.get("使用DNS服务器") != row.get("使用DNS服务器"):
                    issues.append(
                        {"结果编号": code, "字段": "证据摘要.决策.使用DNS服务器", "问题": "证据服务器与结果服务器不一致"}
                    )
            if row.get("冲突裁决"):
                conflict = row.get("冲突裁决") or {}
                if conflict.get("类型") == "CACHE_VS_FAILOVER" and conflict.get("裁决") != "缓存优先":
                    issues.append(
                        {"结果编号": code, "字段": "冲突裁决", "问题": "批次边界冲突未裁决为缓存优先"}
                    )

            # 只有仍生效的结果才要求保留执行协同清单；已合并的历史结果允许被新清单取代。
            if (
                row.get("消费状态") == "已消费"
                and row.get("结果状态") == "生效"
                and code not in manifest_result_codes
            ):
                issues.append({"结果编号": code, "字段": "消费状态", "问题": "已消费结果缺少执行协同清单"})

        # 生效批次唯一性：同一域名 + 配置版本不应同时存在两个生效批次版本。
        active: dict[tuple[str, int], list[str]] = {}
        for row in rows:
            if not row.get("是否成功") or row.get("结果状态") != "生效":
                continue
            key = (normalize_domain(str(row.get("域名", ""))), _as_int(row.get("配置版本"), 0))
            active.setdefault(key, []).append(str(row.get("批次号") or ""))
        for (domain, version), batch_list in active.items():
            distinct = {batch for batch in batch_list if batch}
            if len(distinct) > 1:
                issues.append(
                    {
                        "域名": domain,
                        "字段": "批次版本",
                        "问题": "同一域名与配置版本存在未合并的批次：" + "、".join(sorted(distinct)),
                    }
                )

        # 缓存引用完整性：缓存指向的结果必须存在，地址/版本/来源要一致。
        for cache in store.rows(CACHE_MODULE):
            source_code = str(cache.get("来源结果编号") or "")
            if not source_code:
                issues.append(
                    {"域名": cache.get("域名"), "字段": "来源结果编号", "问题": "缓存未绑定解析结果"}
                )
                continue
            source = codes.get(source_code)
            if source is None:
                issues.append(
                    {"域名": cache.get("域名"), "字段": "来源结果编号", "问题": f"缓存引用的结果 {source_code} 不存在"}
                )
                continue
            if str(source.get("解析地址") or "") != str(cache.get("解析地址") or ""):
                issues.append(
                    {"域名": cache.get("域名"), "字段": "解析地址", "问题": "缓存地址与来源结果不一致"}
                )
            if _as_int(source.get("配置版本"), 0) != _as_int(cache.get("配置版本"), 0):
                issues.append(
                    {"域名": cache.get("域名"), "字段": "配置版本", "问题": "缓存配置版本与来源结果不一致"}
                )

        # 执行协同只消费成功结果。
        for manifest in store.rows(EXEC_MODULE):
            result = codes.get(str(manifest.get("结果编号") or ""))
            if manifest.get("清单状态") == "已消费":
                if result is None:
                    issues.append(
                        {"清单编号": manifest.get("清单编号"), "字段": "结果编号", "问题": "已消费清单引用的结果不存在"}
                    )
                elif not result.get("是否成功"):
                    issues.append(
                        {"清单编号": manifest.get("清单编号"), "字段": "结果编号", "问题": "执行协同消费了失败的解析结果"}
                    )
                elif result.get("消费状态") != "已消费":
                    issues.append(
                        {"清单编号": manifest.get("清单编号"), "字段": "消费状态", "问题": "清单已消费但结果状态未同步"}
                    )

        return {
            "ok": not issues,
            "checked": len(targets),
            "issue_count": len(issues),
            "issues": issues,
            "message": "DNS解析结果数据集完整" if not issues else f"发现 {len(issues)} 处完整性问题",
        }
