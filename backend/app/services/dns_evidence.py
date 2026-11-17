"""DNS解析证据对象与唯一的裁决入口。

缓存命中、主解析超时、故障转移三条路径以前各写一遍判断，容易出现「缓存说一个地址、
故障转移说另一个地址」的分叉。这里把参与判断的输入收拢成 :class:`ResolutionEvidence`，
把结论收拢成 :class:`ResolutionDecision`，并由 :func:`decide_resolution` 单点裁决：

* 配置版本在解析过程中发生切换 -> 旧请求不能把地址写回新版本；
* 缓存必须在 TTL 内、配置版本一致、IPv6 优先级一致才可复用；
* 主解析超时但缓存仍有效时，缓存优先于故障转移（同一 TTL 窗口内结果保持一致）；
* 主解析失败后走故障转移，重试耗尽必须给出明确失败码。

``dnsresult`` 服务只负责取数、落库和加锁，不再自行判断来源或地址。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

FAILURE_CODES: dict[str, str] = {
    "CONFIG_NOT_FOUND": "没有匹配到可用的解析配置",
    "CONFIG_DISABLED": "解析配置未启用，不能用于解析",
    "CONFIG_VERSION_CHANGED": "解析配置在本次解析期间发生版本切换，旧请求不回写新版本地址",
    "RETRY_EXHAUSTED": "主解析与故障转移均已达到重试上限，解析失败",
    "UPSTREAM_FAILURE": "主解析与故障转移均不可用，解析失败",
    "CACHE_VERSION_MISMATCH": "缓存来自旧配置版本，已失效并重新解析",
    "CACHE_IPV6_PRIORITY_CHANGED": "缓存产生于旧IPv6优先级，已失效并重新解析",
    "CACHE_TTL_EXPIRED": "缓存已过期，不能沿用旧解析结果",
}

# 地址来源的固定取值，便于下游执行协同侧按来源校验。
SOURCE_PRIMARY = "主解析"
SOURCE_PRIMARY_IPV6 = "主解析-IPv6"
SOURCE_FAILOVER = "故障转移"
SOURCE_CACHE = "缓存命中"
SOURCE_NONE = "无"

# 故障转移路径的固定前缀，便于追溯。
PATH_NONE = "无"
PATH_PRIMARY_TIMEOUT = "主解析超时→故障转移"
PATH_PRIMARY_FAILURE = "主解析失败→故障转移"
PATH_CACHE_WINS = "缓存命中（未触发故障转移）"


@dataclass(frozen=True)
class AttemptOutcome:
    """单条解析路径的结果。``timeout`` 与 ``ok=False`` 区分超时和明确失败。"""

    ok: bool
    address: str | None = None
    timeout: bool = False
    detail: str = ""

    @property
    def failure_kind(self) -> str:
        if self.ok:
            return "成功"
        return "超时" if self.timeout else "失败"


@dataclass(frozen=True)
class CacheView:
    """缓存的只读快照，是否可用由 :func:`cache_unusable_reason` 给出。"""

    present: bool = False
    record_id: int | None = None
    address: str | None = None
    source: str = SOURCE_NONE
    server: str = ""
    config_version: int | None = None
    ipv6_preferred: str = ""
    batch_id: str = ""
    batch_version: int = 0
    remaining_ttl: int = 0
    result_code: str = ""
    invalid_reason: str = ""


@dataclass(frozen=True)
class ResolutionEvidence:
    """一次解析涉及的全部判断依据。所有路径共用同一份证据。"""

    domain: str
    config_id: int | None
    config_code: str
    config_status: str
    config_version_at_start: int | None
    config_version_now: int | None
    ipv6_preferred: str
    ipv6_address: str
    primary_address: str
    failover_address: str
    primary_server: str
    failover_server: str
    timeout_ms: int
    ttl_seconds: int
    retry_limit: int
    attempts: int
    primary: AttemptOutcome
    failover: AttemptOutcome
    cache: CacheView
    batch_id: str = ""
    batch_version: int = 0
    merge_batch_ids: tuple[str, ...] = ()
    refresh: bool = False
    # 本次请求是否真实探测了主解析（强制刷新、显式指定解析状态、或配置本身主解析异常）。
    primary_attempted: bool = False
    notes: list[str] = field(default_factory=list)

    def base(self) -> dict[str, Any]:
        """证据摘要：随解析结果一起落库，保证服务器与故障转移路径可追溯。"""
        return {
            "域名": self.domain,
            "配置编号": self.config_code,
            "配置版本": self.config_version_now,
            "配置版本(开始时)": self.config_version_at_start,
            "尝试次数": self.attempts,
            "重试上限": self.retry_limit,
            "缓存": {
                "存在": self.cache.present,
                "可复用": cache_unusable_reason(self) == "",
                "地址": self.cache.address,
                "配置版本": self.cache.config_version,
                "剩余TTL秒": self.cache.remaining_ttl,
                "批次号": self.cache.batch_id,
                "失效原因": cache_unusable_reason(self),
            },
            "主解析": {
                "服务器": self.primary_server,
                "状态": self.primary.failure_kind,
                "地址": self.primary.address,
                "本次探测": self.primary_attempted,
            },
            "故障转移": {
                "服务器": self.failover_server,
                "状态": self.failover.failure_kind,
                "地址": self.failover.address,
            },
            "批次": {"批次号": self.batch_id, "批次版本": self.batch_version},
        }


@dataclass(frozen=True)
class ResolutionDecision:
    ok: bool
    address: str
    source: str
    failover_path: str
    server: str
    failure_code: str
    failure_reason: str
    retry_count: int
    cache_status: str
    reuse_result_code: str = ""
    conflict: dict[str, Any] | None = None
    notes: tuple[str, ...] = ()

    def summary(self) -> dict[str, Any]:
        return {
            "成功": self.ok,
            "地址": self.address,
            "地址来源": self.source,
            "故障转移路径": self.failover_path,
            "使用DNS服务器": self.server,
            "失败码": self.failure_code,
            "失败原因": self.failure_reason,
            "重试次数": self.retry_count,
            "缓存状态": self.cache_status,
            "冲突裁决": self.conflict,
        }


def cache_unusable_reason(evidence: ResolutionEvidence) -> str:
    """缓存能否复用的唯一判断：TTL、配置版本、IPv6 优先级三项缺一不可。"""
    cache = evidence.cache
    if not cache.present:
        return "无缓存"
    if cache.invalid_reason:
        return cache.invalid_reason
    if not str(cache.address or "").strip():
        # 缓存没有地址（可能来自未完成的写入）不能当命中用。
        return "缓存缺少地址"
    if cache.config_version != evidence.config_version_now:
        return "CACHE_VERSION_MISMATCH"
    if cache.ipv6_preferred != evidence.ipv6_preferred:
        return "CACHE_IPV6_PRIORITY_CHANGED"
    if cache.remaining_ttl <= 0:
        return "CACHE_TTL_EXPIRED"
    return ""


def _cache_hit(
    evidence: ResolutionEvidence,
    reason: str,
) -> ResolutionDecision:
    """已确定使用缓存时的统一结论（含主解析超时与故障转移的冲突裁决）。"""
    cache = evidence.cache
    conflict: dict[str, Any] | None = None
    path = PATH_NONE
    # 批次边界冲突：主解析刚超时、缓存仍有剩余 TTL，缓存与故障转移都能给地址。
    if not evidence.primary.ok and evidence.failover.ok:
        conflict = {
            "类型": "CACHE_VS_FAILOVER",
            "缓存地址": cache.address,
            "故障转移地址": evidence.failover.address,
            "裁决": "缓存优先",
            "依据": "同一TTL窗口内保留一致结果，且缓存配置版本与IPv6优先级均一致",
        }
        path = PATH_CACHE_WINS
    notes = list(evidence.notes)
    notes.append("缓存命中：" + reason)
    return ResolutionDecision(
        ok=True,
        address=str(cache.address),
        source=SOURCE_CACHE,
        failover_path=path,
        server=cache.server or evidence.failover_server or evidence.primary_server,
        failure_code="",
        failure_reason="",
        retry_count=max(evidence.attempts - 1, 0),
        cache_status="命中",
        reuse_result_code=cache.result_code,
        conflict=conflict,
        notes=tuple(notes),
    )


def _fresh_success(
    evidence: ResolutionEvidence,
    outcome: AttemptOutcome,
    source: str,
    path: str,
    retry_count: int,
    cache_status: str,
) -> ResolutionDecision:
    notes = list(evidence.notes)
    if evidence.merge_batch_ids:
        notes.append("已合并旧批次：" + "、".join(evidence.merge_batch_ids))
    return ResolutionDecision(
        ok=True,
        address=str(outcome.address),
        source=source,
        failover_path=path,
        server=evidence.primary_server if source.startswith(SOURCE_PRIMARY) else evidence.failover_server,
        failure_code="",
        failure_reason="",
        retry_count=retry_count,
        cache_status=cache_status,
        notes=tuple(notes),
    )


def _failure(
    evidence: ResolutionEvidence,
    code: str,
    reason: str,
    retry_count: int,
    cache_status: str,
    path: str = PATH_NONE,
) -> ResolutionDecision:
    return ResolutionDecision(
        ok=False,
        address="",
        source=SOURCE_NONE,
        failover_path=path,
        server=evidence.primary_server,
        failure_code=code,
        failure_reason=reason,
        retry_count=retry_count,
        cache_status=cache_status,
        notes=tuple(evidence.notes),
    )


def decide_resolution(evidence: ResolutionEvidence) -> ResolutionDecision:
    """唯一裁决入口：输入证据，输出地址来源、服务器、路径与失败码。"""
    # 1. 配置切换期间旧请求不能把地址写回新版本。
    if (
        evidence.config_version_at_start is not None
        and evidence.config_version_now is not None
        and evidence.config_version_at_start != evidence.config_version_now
    ):
        return _failure(
            evidence,
            "CONFIG_VERSION_CHANGED",
            f"{FAILURE_CODES['CONFIG_VERSION_CHANGED']}：开始时 v{evidence.config_version_at_start}，"
            f"当前 v{evidence.config_version_now}",
            retry_count=max(evidence.attempts - 1, 0),
            cache_status="未使用",
        )

    if evidence.config_id is None:
        return _failure(
            evidence,
            "CONFIG_NOT_FOUND",
            FAILURE_CODES["CONFIG_NOT_FOUND"],
            retry_count=0,
            cache_status="未使用",
        )

    if evidence.config_status != "已启用":
        return _failure(
            evidence,
            "CONFIG_DISABLED",
            f"{FAILURE_CODES['CONFIG_DISABLED']}（{evidence.config_code} 当前为{evidence.config_status}）",
            retry_count=0,
            cache_status="未使用",
        )

    cache_reason = cache_unusable_reason(evidence)

    # 2. 缓存可复用但本次真实探测了主解析：主解析与缓存不一致时以最新主解析为准，
    #    但主解析超时/失败而缓存仍有效时缓存优先，避免缓存与故障转移给出不同来源。
    if not evidence.refresh and evidence.primary_attempted:
        cache_usable = cache_reason == ""
        if cache_usable and evidence.primary.ok:
            if evidence.ipv6_preferred == "是" and evidence.ipv6_address:
                return _fresh_success(
                    evidence,
                    AttemptOutcome(ok=True, address=evidence.ipv6_address),
                    SOURCE_PRIMARY_IPV6,
                    PATH_NONE,
                    max(evidence.attempts - 1, 0),
                    "已刷新",
                )
            return _fresh_success(
                evidence,
                evidence.primary,
                SOURCE_PRIMARY,
                PATH_NONE,
                max(evidence.attempts - 1, 0),
                "已刷新",
            )
        if cache_usable and not evidence.primary.ok:
            return _cache_hit(evidence, "主解析" + evidence.primary.failure_kind + "，缓存仍有剩余TTL")

    # 3. 缓存可复用且未重新探测：直接给出与缓存一致的结论，不产生分叉。
    if cache_reason == "" and not evidence.refresh:
        return _cache_hit(evidence, "TTL内复用，配置版本与IPv6优先级一致")

    # 4. 主解析成功：按 IPv6 优先级决定地址。
    if evidence.primary.ok:
        if evidence.ipv6_preferred == "是" and evidence.ipv6_address:
            return _fresh_success(
                evidence,
                AttemptOutcome(ok=True, address=evidence.ipv6_address),
                SOURCE_PRIMARY_IPV6,
                PATH_NONE,
                max(evidence.attempts - 1, 0),
                "未使用" if cache_reason == "无缓存" else "失效重取",
            )
        return _fresh_success(
            evidence,
            evidence.primary,
            SOURCE_PRIMARY,
            PATH_NONE,
            max(evidence.attempts - 1, 0),
            "未使用" if cache_reason == "无缓存" else "失效重取",
        )

    # 5. 主解析失败但缓存仍有效：缓存优先于故障转移，保证同一 TTL 窗口结果一致。
    if cache_reason == "":
        return _cache_hit(evidence, "主解析" + evidence.primary.failure_kind + "，缓存仍有剩余TTL")

    # 6. 主解析失败、缓存不可用、故障转移成功。
    if evidence.failover.ok:
        path = PATH_PRIMARY_TIMEOUT if evidence.primary.timeout else PATH_PRIMARY_FAILURE
        return _fresh_success(
            evidence,
            evidence.failover,
            SOURCE_FAILOVER,
            path,
            max(evidence.attempts - 1, 0),
            "未使用" if cache_reason == "无缓存" else "失效重取",
        )

    # 7. 主解析与故障转移都失败：重试耗尽给明确失败，否则给上游失败。
    if evidence.attempts >= evidence.retry_limit:
        return _failure(
            evidence,
            "RETRY_EXHAUSTED",
            f"{FAILURE_CODES['RETRY_EXHAUSTED']}（已尝试 {evidence.attempts}/{evidence.retry_limit} 次）",
            retry_count=max(evidence.attempts - 1, 0),
            cache_status="未使用" if cache_reason == "无缓存" else "失效重取",
        )
    return _failure(
        evidence,
        "UPSTREAM_FAILURE",
        FAILURE_CODES["UPSTREAM_FAILURE"],
        retry_count=max(evidence.attempts - 1, 0),
        cache_status="未使用" if cache_reason == "无缓存" else "失效重取",
    )
