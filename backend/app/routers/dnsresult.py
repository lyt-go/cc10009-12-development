"""DNS解析结果接口：解析追踪、结果数据集、缓存、批次与执行协同清单。

结果数据集里的每条记录都绑定配置版本、实际使用的 DNS 服务器、故障转移路径、
批次与证据摘要，并支持完整性校验；执行协同侧只消费成功结果，失败原因写回采集记录。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.schemas import ActionResult, EntryPayload, PageResult
from app.services.dnsresult import RESULT_LIFECYCLE, TRACE_FIELDS, DnsresultService

router = APIRouter(prefix="/api/dnsresult", tags=["DNS解析结果"])

service = DnsresultService()

LIST_FIELDS = TRACE_FIELDS + ["解析地址", "批次号", "批次版本", "结果状态", "消费状态", "失败码"]


@router.get("", response_model=PageResult[dict])
def list_entries(
    keyword: str | None = Query(default=None, description="按结果编号或域名检索"),
    status: str | None = Query(default=None, description="成功、失败"),
    domain: str | None = Query(default=None, description="按域名精确检索"),
    page: int = 1,
    size: int = 20,
) -> PageResult[dict]:
    """按结果编号、状态与域名过滤DNS解析结果；没有数据时返回空页，不报错。"""
    if size > 200:
        raise HTTPException(status_code=400, detail="每页最多 200 条，请缩小分页范围")
    items, total = service.list_entries(keyword=keyword, status=status, domain=domain, page=page, size=size)
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/stats", response_model=dict)
def get_stats() -> dict[str, Any]:
    """结果、缓存与执行协同清单的汇总指标。"""
    return service.stats()


@router.get("/caches", response_model=dict)
def list_caches(domain: str | None = Query(default=None)) -> dict[str, Any]:
    """查看DNS缓存快照，便于核对 TTL、配置版本与 IPv6 优先级是否可复用。"""
    items = service.list_caches(domain)
    return {"total": len(items), "items": items}


@router.get("/batches", response_model=dict)
def list_batches(domain: str | None = Query(default=None)) -> dict[str, Any]:
    """查看解析批次；同一域名同一配置只应存在一个生效批次版本。"""
    items = service.list_batches(domain)
    return {"total": len(items), "items": items}


@router.get("/execution-manifest", response_model=dict)
def list_execution_manifest(domain: str | None = Query(default=None)) -> dict[str, Any]:
    """执行协同侧清单：只包含成功解析结果，失败原因留在采集记录上。"""
    items = service.list_execution_manifest(domain)
    return {"total": len(items), "items": items}


@router.get("/crawl-records", response_model=dict)
def list_crawl_records(domain: str | None = Query(default=None)) -> dict[str, Any]:
    """采集记录：解析成功写入地址，解析失败写入失败码与原因。"""
    items = service.list_crawl_records(domain)
    return {"total": len(items), "items": items}


@router.get("/verify", response_model=dict)
def verify_dataset(entry_id: int | None = Query(default=None, description="只校验单条结果")) -> dict[str, Any]:
    """校验DNS解析结果数据集的完整性：追溯字段、批次、缓存引用、证据与消费链路。"""
    return service.verify(entry_id)


@router.post("/resolve", response_model=ActionResult)
def resolve(payload: EntryPayload) -> ActionResult:
    """解析一个域名并生成结果数据集。

    支持字段：域名、作业编号、采集URL、尝试次数、刷新、配置编号/配置ID、
    配置版本快照、主解析状态、故障转移状态。缺域名或配置不可用时给出可读原因。
    """
    result, message = service.resolve(payload.values)
    if result is None:
        return ActionResult(ok=False, message=message)
    return ActionResult(ok=bool(result.get("是否成功")), message=message, entry=result)


@router.post("/consume", response_model=ActionResult)
def consume() -> ActionResult:
    """执行协同侧消费所有待消费的成功结果；失败结果标记为不可消费并保留原因。"""
    summary = service.consume_ready()
    return ActionResult(
        ok=True,
        message=(
            f"执行协同已消费 {summary['consumed']} 条成功结果，"
            f"拦截 {summary['blocked']} 条失败结果"
        ),
        entry=summary,
    )


@router.get("/export")
def export_entries() -> dict[str, Any]:
    """导出DNS解析结果数据集：返回全量结果，供离线核对与入库。"""
    items, total = service.list_entries(page=1, size=10000)
    return {
        "module": "dnsresult",
        "total": total,
        "fields": LIST_FIELDS,
        "lifecycle": RESULT_LIFECYCLE,
        "items": items,
    }


# 注意：带路径参数的详情接口必须放在所有静态路径之后，否则 /export、/verify
# 这类路径会先被 int 解析拦下，返回 422 而不是数据。
@router.get("/{entry_id}", response_model=dict)
def get_entry(entry_id: int) -> dict:
    """读取单条DNS解析结果明细；不存在时给出可读的错误说明。"""
    entry = service.get_entry(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"DNS解析结果 {entry_id} 不存在或已归档")
    return entry
