"""DNS解析业务规则：状态流转、字段校验与筛选口径都收在这里。"""
from __future__ import annotations

from typing import Any

from app.store import store

MODULE = "dnsresolver"
REQUIRED_FIELDS = ["配置编号", "域名模式", "DNS服务器"]
STATUS_ORDER = ["草稿", "配置测试中", "已启用", "已降级"]
ACTION_RULES = {"提交配置测试": "配置测试中", "启用配置": "已启用", "降级配置": "已降级"}
NEGATIVE_ACTIONS = []


class DnsresolverService:
    def list_entries(
        self,
        *,
        keyword: str | None = None,
        status: str | None = None,
        page: int = 1,
        size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        rows = store.rows(MODULE)
        if keyword:
            rows = [row for row in rows if keyword in str(row.get("配置编号", ""))]
        if status:
            rows = [row for row in rows if row.get("status") == status]
        total = len(rows)
        start = max(page - 1, 0) * size
        return rows[start:start + size], total

    def get_entry(self, entry_id: int) -> dict[str, Any] | None:
        return store.find(MODULE, entry_id)

    def create_entry(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        missing = [field for field in REQUIRED_FIELDS if not str(values.get(field) or "").strip()]
        if missing:
            return None, missing
        rows = store.rows(MODULE)
        entry = {"id": max((int(row.get("id", 0)) for row in rows), default=0) + 1}
        entry.update({field: values.get(field) for field in REQUIRED_FIELDS})
        entry["status"] = STATUS_ORDER[0]
        entry["pending"] = True
        entry["abnormal"] = False
        rows.append(entry)
        return entry, []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"解析配置 {entry_id} 不存在或已归档"
        if action not in ACTION_RULES:
            return None, f"动作「{action}」不属于DNS解析可执行范围"
        target = ACTION_RULES[action]
        if target not in STATUS_ORDER:
            return None, f"目标状态「{target}」不在允许的状态序列里"
        entry["status"] = target
        entry["pending"] = target != STATUS_ORDER[-1]
        entry["abnormal"] = action in NEGATIVE_ACTIONS
        return entry, f"解析配置已{action}"

    # 允许通过版本发布更新的字段；域名模式即「绑定域名」，变更同样要求升版本。
    PUBLISH_FIELDS = [
        "域名模式",
        "DNS服务器",
        "解析超时毫秒",
        "缓存TTL秒",
        "A记录策略",
        "IPv6优先",
        "故障转移地址",
        "主解析地址",
        "IPv6地址",
        "故障转移DNS服务器",
        "重试上限",
        "主解析状态",
        "故障转移状态",
    ]

    def publish_version(self, entry_id: int, values: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
        """发布配置新版本：升版本号并让旧缓存立即失效，旧请求无法再回写新版本地址。

        未提供任何可发布字段时不做空发布，避免版本号无意义地增长。
        """
        entry = store.find(MODULE, entry_id)
        if entry is None:
            return None, f"解析配置 {entry_id} 不存在或已归档"
        updates = {
            field: values[field]
            for field in self.PUBLISH_FIELDS
            if field in values and values[field] is not None
        }
        if not updates:
            return None, "没有可发布的配置字段，版本未变更"
        changed = {
            field: {"旧值": entry.get(field), "新值": value}
            for field, value in updates.items()
            if str(entry.get(field) or "") != str(value or "")
        }
        if not changed:
            return entry, "配置字段无变化，版本未变更"
        entry.update(updates)
        entry["配置版本"] = int(entry.get("配置版本") or 0) + 1
        from datetime import datetime, timezone

        entry["版本更新时间"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        # 配置切换后旧缓存不能再被复用：标为失效并记录原因。
        from app.services.dnsresult import DnsresultService

        invalidated = DnsresultService().invalidate_domain_caches(
            str(entry.get("域名模式") or ""),
            reason="CONFIG_VERSION_MISMATCH",
        )
        return entry, (
            f"解析配置已发布到 v{entry['配置版本']}，"
            f"变更字段 {len(changed)} 项，失效缓存 {invalidated} 条"
        )
