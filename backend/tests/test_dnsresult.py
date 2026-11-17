"""DNS解析结果追踪的回归测试。

覆盖：解析结果绑定配置版本/服务器/故障转移路径、完整性校验、缓存过期不复用旧版本、
IPv6 优先级变化、批次边界冲突裁决为缓存优先、配置切换期间旧请求不回写、
重试上限明确失败、幂等只计一次、并发不分叉、执行协同只消费成功结果。

运行：backend/.venv/bin/python -m unittest discover -s backend/tests -v
"""
from __future__ import annotations

import sys
import threading
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from app.services.dns_evidence import decide_resolution  # noqa: E402
from app.services.dnsresult import DnsresultService  # noqa: E402
from app.services.dnsresolver import DnsresolverService  # noqa: E402
from app.store import store  # noqa: E402


def reset_store() -> None:
    """每个用例拿到一份干净的示例数据，避免用例之间互相污染。"""
    from app.seed import SEED_ROWS

    store._tables = {name: [dict(row) for row in rows] for name, rows in SEED_ROWS.items()}


class DnsResultTestCase(unittest.TestCase):
    def setUp(self) -> None:
        reset_store()
        self.service = DnsresultService()

    def results_for(self, domain: str) -> list[dict]:
        return [row for row in store.rows("dnsresult") if row["域名"] == domain]

    def test_result_binds_config_version_server_and_path(self) -> None:
        entry, message = self.service.resolve({"域名": "cdn.example.net"})
        self.assertIsNotNone(entry)
        self.assertTrue(entry["是否成功"], message)
        self.assertEqual(entry["配置版本"], 1)
        self.assertEqual(entry["使用DNS服务器"], "223.5.5.5:53")
        self.assertEqual(entry["故障转移路径"], "无")
        self.assertEqual(entry["地址来源"], "主解析")
        self.assertIn("主解析", entry["证据摘要"])
        self.assertIn("故障转移", entry["证据摘要"])

    def test_dataset_verifiable_at_start(self) -> None:
        report = self.service.verify()
        self.assertTrue(report["ok"], report["issues"])

    def test_verify_detects_broken_evidence(self) -> None:
        entry, _ = self.service.resolve({"域名": "cdn.example.net"})
        stored = self.service.get_entry(entry["id"])
        stored["使用DNS服务器"] = "198.51.100.254:53"
        report = self.service.verify(entry["id"])
        self.assertFalse(report["ok"])
        self.assertTrue(any("服务器" in issue.get("字段", "") for issue in report["issues"]))

    def test_resolve_returns_copy_not_store_row(self) -> None:
        entry, _ = self.service.resolve({"域名": "cdn.example.net"})
        entry["解析地址"] = "10.0.0.1"
        stored = self.service.get_entry(entry["id"])
        self.assertEqual(stored["解析地址"], "198.51.100.61")
        self.assertTrue(self.service.verify()["ok"])

    def test_repeat_processing_counts_once(self) -> None:
        first, _ = self.service.resolve({"域名": "example.com"})
        before = len(store.rows("dnsresult"))
        second, message = self.service.resolve({"域名": "example.com"})
        self.assertEqual(len(store.rows("dnsresult")), before)
        self.assertEqual(first["结果编号"], second["结果编号"])
        self.assertIn("幂等", message)

    def test_expired_cache_does_not_reuse_old_address(self) -> None:
        entry, _ = self.service.resolve({"域名": "stale.example.com"})
        self.assertEqual(entry["地址来源"], "主解析")
        self.assertEqual(entry["解析地址"], "198.51.100.71")
        self.assertNotEqual(entry["解析地址"], "198.51.100.70")
        cache = [row for row in store.rows("dnscache") if row["域名"] == "stale.example.com"][0]
        self.assertEqual(cache["解析地址"], "198.51.100.71")
        self.assertIn(entry["批次号"], cache["批次号"])

    def test_ipv6_priority_change_does_not_reuse_old_address(self) -> None:
        entry, _ = self.service.resolve({"域名": "ipv6.example.com"})
        self.assertEqual(entry["地址来源"], "主解析-IPv6")
        self.assertEqual(entry["解析地址"], "2001:db8:6::91")

    def test_ttl_window_keeps_consistent_result(self) -> None:
        first, _ = self.service.resolve({"域名": "cdn.example.net"})
        second, _ = self.service.resolve({"域名": "cdn.example.net"})
        self.assertEqual(first["结果编号"], second["结果编号"])
        self.assertEqual(first["解析地址"], second["解析地址"])

    def test_batch_conflict_resolves_to_cache(self) -> None:
        entry, message = self.service.resolve({"域名": "conflict.example.com", "刷新": True})
        self.assertEqual(entry["地址来源"], "缓存命中")
        self.assertEqual(entry["解析地址"], "198.51.100.100")
        self.assertEqual(entry["故障转移路径"], "缓存命中（未触发故障转移）")
        conflict = entry["冲突裁决"]
        self.assertEqual(conflict["类型"], "CACHE_VS_FAILOVER")
        self.assertEqual(conflict["裁决"], "缓存优先")
        self.assertEqual(conflict["故障转移地址"], "203.0.113.129")
        self.assertIn("缓存优先", message)
        self.assertTrue(self.service.verify(entry["id"])["ok"])

    def test_old_request_does_not_write_back_new_version(self) -> None:
        DnsresolverService().publish_version(1, {"主解析地址": "93.184.216.99"})
        entry, _ = self.service.resolve({"域名": "example.com", "配置版本快照": 1})
        self.assertFalse(entry["是否成功"])
        self.assertEqual(entry["失败码"], "CONFIG_VERSION_CHANGED")
        config = [row for row in store.rows("dnsresolver") if row["id"] == 1][0]
        fresh, _ = self.service.resolve({"域名": "example.com", "刷新": True})
        self.assertEqual(fresh["配置版本"], config["配置版本"])
        self.assertEqual(fresh["解析地址"], "93.184.216.99")

    def test_retry_limit_returns_explicit_failure(self) -> None:
        entry, message = self.service.resolve(
            {
                "域名": "cdn.example.net",
                "主解析状态": "失败",
                "故障转移状态": "超时",
                "尝试次数": 3,
            }
        )
        self.assertFalse(entry["是否成功"])
        self.assertEqual(entry["失败码"], "RETRY_EXHAUSTED")
        self.assertIn("RETRY_EXHAUSTED", message)
        record = [row for row in store.rows("crawlrecord") if row["域名"] == "cdn.example.net"][0]
        self.assertEqual(record["失败码"], "RETRY_EXHAUSTED")
        self.assertEqual(record["解析状态"], "失败")

    def test_failover_path_is_traceable_when_primary_times_out(self) -> None:
        entry, _ = self.service.resolve({"域名": "cdn.example.net", "主解析状态": "超时"})
        self.assertTrue(entry["是否成功"])
        self.assertEqual(entry["地址来源"], "故障转移")
        self.assertEqual(entry["解析地址"], "203.0.113.69")
        self.assertEqual(entry["故障转移路径"], "主解析超时→故障转移")
        self.assertEqual(entry["使用DNS服务器"], "223.5.5.5:53(备用)")
        self.assertTrue(self.service.verify(entry["id"])["ok"])

    def test_disabled_config_is_rejected_before_resolution(self) -> None:
        entry, _ = self.service.resolve({"域名": "api.example.org"})
        self.assertFalse(entry["是否成功"])
        self.assertEqual(entry["失败码"], "CONFIG_DISABLED")

    def test_execution_manifest_only_consumes_success(self) -> None:
        success, _ = self.service.resolve({"域名": "cdn.example.net"})
        failure, _ = self.service.resolve(
            {
                "域名": "stale.example.com",
                "主解析状态": "失败",
                "故障转移状态": "失败",
                "尝试次数": 3,
            }
        )
        manifest = {row["结果编号"]: row for row in store.rows("executioncoord")}
        self.assertEqual(manifest[success["结果编号"]]["清单状态"], "待消费")
        self.assertNotIn(failure["结果编号"], manifest)
        summary = self.service.consume_ready()
        self.assertEqual(summary["consumed"], 1)
        self.assertEqual(manifest[success["结果编号"]]["清单状态"], "已消费")
        self.assertEqual(manifest[success["结果编号"]]["使用DNS服务器"], "223.5.5.5:53")
        self.assertTrue(self.service.verify()["ok"], self.service.verify()["issues"])

    def test_concurrent_same_domain_is_single_flight(self) -> None:
        workers = 10
        barrier = threading.Barrier(workers)
        codes: list[str] = []
        addresses: list[str] = []
        errors: list[str] = []

        def run() -> None:
            try:
                barrier.wait()
                entry, _ = self.service.resolve({"域名": "cdn.example.net"})
                codes.append(entry["结果编号"])
                addresses.append(entry["解析地址"])
            except Exception as error:  # pragma: no cover - 失败时把异常带到断言里
                errors.append(repr(error))

        threads = [threading.Thread(target=run) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(len(set(codes)), 1)
        self.assertEqual(len(set(addresses)), 1)
        self.assertEqual(len(self.results_for("cdn.example.net")), 1)
        active_batches = [
            row
            for row in store.rows("dnsbatch")
            if row["域名"] == "cdn.example.net" and row["状态"] == "生效"
        ]
        self.assertEqual(len(active_batches), 1)
        self.assertTrue(self.service.verify()["ok"], self.service.verify()["issues"])

    def test_same_domain_and_version_has_one_active_batch(self) -> None:
        self.service.resolve({"域名": "cdn.example.net"})
        self.service.resolve({"域名": "cdn.example.net", "刷新": True})
        active = [
            row
            for row in store.rows("dnsbatch")
            if row["域名"] == "cdn.example.net" and row["状态"] == "生效"
        ]
        self.assertEqual(len(active), 1)
        self.assertTrue(self.service.verify()["ok"])

    def test_published_version_invalidates_cache_within_ttl(self) -> None:
        # example.com 缓存仍在 TTL 内，但发布新版本后不允许再复用旧版本缓存。
        before, _ = self.service.resolve({"域名": "example.com"})
        self.assertEqual(before["地址来源"], "主解析")
        DnsresolverService().publish_version(1, {"主解析地址": "93.184.216.99"})
        after, _ = self.service.resolve({"域名": "example.com"})
        self.assertEqual(after["配置版本"], before["配置版本"] + 1)
        self.assertEqual(after["解析地址"], "93.184.216.99")
        cache = [row for row in store.rows("dnscache") if row["域名"] == "example.com"][0]
        self.assertEqual(cache["配置版本"], after["配置版本"])
        self.assertEqual(cache["解析地址"], "93.184.216.99")

    def test_decide_resolution_is_shared_entry_point(self) -> None:
        self.assertTrue(callable(decide_resolution))


if __name__ == "__main__":
    unittest.main()
