import { useCallback, useEffect, useMemo, useState } from 'react'

import { fetchJson, request } from '@/api/client'

const ENDPOINT = '/api/dnsresult'
const columns = [
  '结果编号',
  '域名',
  '配置编号',
  '配置版本',
  '地址来源',
  '使用DNS服务器',
  '故障转移路径',
  '解析地址',
  '批次号',
  '结果状态',
  '消费状态',
]

type Row = Record<string, string | number | boolean | null | Record<string, unknown>>
type Stats = Record<string, number>
type VerifyResult = {
  ok: boolean
  checked: number
  issue_count: number
  message: string
  issues: Record<string, string>[]
}
type ManifestRow = Record<string, string | number | null>
type CrawlRow = Record<string, string | number | null>

const emptyVerify: VerifyResult = { ok: true, checked: 0, issue_count: 0, message: '', issues: [] }

export default function DnsresultView() {
  const [rows, setRows] = useState<Row[]>([])
  const [total, setTotal] = useState(0)
  const [stats, setStats] = useState<Stats>({})
  const [manifest, setManifest] = useState<ManifestRow[]>([])
  const [crawlRecords, setCrawlRecords] = useState<CrawlRow[]>([])
  const [verification, setVerification] = useState<VerifyResult>(emptyVerify)
  const [domainInput, setDomainInput] = useState('')
  const [refresh, setRefresh] = useState(false)
  const [errorMessage, setErrorMessage] = useState('')
  const [notice, setNotice] = useState('')
  const [filters, setFilters] = useState<Record<string, string>>({})
  const filterFields = useMemo(() => columns.slice(0, 2), [])

  const loadAll = useCallback(async () => {
    setErrorMessage('')
    const query = new URLSearchParams(filters).toString()
    try {
      const [list, statPayload, manifestPayload, crawlPayload] = await Promise.all([
        request(`${ENDPOINT}?${query}`).then((res) => res.json()),
        fetchJson<Stats>(`${ENDPOINT}/stats`),
        fetchJson<{ items: ManifestRow[] }>(`${ENDPOINT}/execution-manifest`),
        fetchJson<{ items: CrawlRow[] }>(`${ENDPOINT}/crawl-records`),
      ])
      setRows(list.items ?? [])
      setTotal(list.total ?? 0)
      setStats(statPayload)
      setManifest(manifestPayload.items ?? [])
      setCrawlRecords(crawlPayload.items ?? [])
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'DNS解析结果读取失败')
    }
  }, [filters])

  useEffect(() => {
    void loadAll()
  }, [loadAll])

  async function runResolve() {
    setErrorMessage('')
    setNotice('')
    try {
      const response = await request(`${ENDPOINT}/resolve`, {
        method: 'POST',
        body: JSON.stringify({ values: { 域名: domainInput.trim(), 刷新: refresh } }),
      })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error('解析请求未生效，请稍后重试')
      }
      setNotice(payload.message ?? '')
      if (!payload.ok) {
        setErrorMessage(payload.message ?? '')
      }
      await loadAll()
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'DNS解析操作失败')
    }
  }

  async function runVerify(entryId?: number) {
    setErrorMessage('')
    try {
      const path = entryId ? `${ENDPOINT}/verify?entry_id=${entryId}` : `${ENDPOINT}/verify`
      const payload = await fetchJson<VerifyResult>(path)
      setVerification(payload)
      setNotice(payload.message)
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '完整性校验失败')
    }
  }

  async function runConsume() {
    setErrorMessage('')
    try {
      const response = await request(`${ENDPOINT}/consume`, { method: 'POST' })
      const payload = await response.json()
      if (!response.ok) {
        throw new Error('执行协同消费未生效，请稍后重试')
      }
      setNotice(payload.message ?? '')
      await loadAll()
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '执行协同消费失败')
    }
  }

  return (
    <section className="page" data-module="dnsresult">
      <header className="page-head">
        <div>
          <h2>DNS解析结果追踪</h2>
          <p className="page-desc">
            每次解析绑定配置版本、实际使用的DNS服务器与故障转移路径；结果数据集可校验，执行协同只消费成功结果。
          </p>
        </div>
        <div className="page-actions">
          <button className="btn primary" type="button" onClick={() => void runVerify()}>
            校验数据集完整性
          </button>
          <button className="btn" type="button" onClick={() => void runConsume()}>
            执行协同消费
          </button>
          <button className="btn" type="button" onClick={() => window.open(`${ENDPOINT}/export`, '_blank')}>
            导出解析结果
          </button>
        </div>
      </header>

      <div className="stat-row">
        {[
          ['结果总数', stats['结果总数']],
          ['成功结果', stats['成功结果']],
          ['失败结果', stats['失败结果']],
          ['已合并批次', stats['已合并结果']],
          ['待消费清单', stats['待消费清单']],
        ].map(([label, value]) => (
          <article key={String(label)} className="stat-card">
            <span className="stat-label">{label}</span>
            <strong className="stat-value">{value ?? 0}</strong>
          </article>
        ))}
      </div>

      <form
        className="filter-bar"
        onSubmit={(event) => {
          event.preventDefault()
          void loadAll()
        }}
      >
        <label className="filter-item">
          <span>解析域名</span>
          <input
            value={domainInput}
            placeholder="例如 example.com"
            onChange={(event) => setDomainInput(event.target.value)}
          />
        </label>
        <label className="filter-item">
          <span>刷新缓存</span>
          <input type="checkbox" checked={refresh} onChange={(event) => setRefresh(event.target.checked)} />
        </label>
        <button className="btn primary" type="button" onClick={() => void runResolve()}>
          执行解析
        </button>
        {filterFields.map((field) => (
          <label key={field} className="filter-item">
            <span>{field}</span>
            <input
              value={filters[field] ?? ''}
              placeholder={`按${field}检索`}
              onChange={(event) => setFilters((prev) => ({ ...prev, [field]: event.target.value }))}
            />
          </label>
        ))}
        <button className="btn" type="submit">查询</button>
        <button className="btn ghost" type="button" onClick={() => setFilters({})}>重置条件</button>
      </form>

      <table className="data-table">
        <thead>
          <tr>
            {columns.map((column) => <th key={column}>{column}</th>)}
            <th>完整性</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={String(row.id)}>
              {columns.map((column) => <td key={column}>{String(row[column] ?? '—')}</td>)}
              <td className="row-actions">
                <button className="link" type="button" onClick={() => void runVerify(Number(row.id))}>
                  校验单条
                </button>
              </td>
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td className="empty-state" colSpan={columns.length + 1}>暂无DNS解析结果，可先执行一次解析</td>
            </tr>
          )}
        </tbody>
      </table>

      <h3>执行协同清单</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>清单编号</th>
            <th>域名</th>
            <th>结果编号</th>
            <th>解析地址</th>
            <th>地址来源</th>
            <th>配置版本</th>
            <th>使用DNS服务器</th>
            <th>故障转移路径</th>
            <th>清单状态</th>
            <th>消费时间</th>
          </tr>
        </thead>
        <tbody>
          {manifest.map((row) => (
            <tr key={String(row.id)}>
              <td>{row['清单编号'] ?? '—'}</td>
              <td>{row['域名'] ?? '—'}</td>
              <td>{row['结果编号'] ?? '—'}</td>
              <td>{row['解析地址'] ?? '—'}</td>
              <td>{row['地址来源'] ?? '—'}</td>
              <td>{row['配置版本'] ?? '—'}</td>
              <td>{row['使用DNS服务器'] ?? '—'}</td>
              <td>{row['故障转移路径'] ?? '—'}</td>
              <td>{row['清单状态'] ?? '—'}</td>
              <td>{row['消费时间'] || '—'}</td>
            </tr>
          ))}
          {manifest.length === 0 && (
            <tr><td className="empty-state" colSpan={10}>暂无执行协同清单，成功解析后自动生成</td></tr>
          )}
        </tbody>
      </table>

      <h3>采集记录（解析失败原因写回）</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>记录编号</th>
            <th>域名</th>
            <th>作业编号</th>
            <th>解析结果编号</th>
            <th>解析状态</th>
            <th>解析地址</th>
            <th>失败码</th>
            <th>失败原因</th>
          </tr>
        </thead>
        <tbody>
          {crawlRecords.map((row) => (
            <tr key={String(row.id)}>
              <td>{row['记录编号'] ?? '—'}</td>
              <td>{row['域名'] ?? '—'}</td>
              <td>{row['作业编号'] || '—'}</td>
              <td>{row['解析结果编号'] || '—'}</td>
              <td>{row['解析状态'] ?? '—'}</td>
              <td>{row['解析地址'] || '—'}</td>
              <td>{row['失败码'] || '—'}</td>
              <td>{row['失败原因'] || '—'}</td>
            </tr>
          ))}
          {crawlRecords.length === 0 && (
            <tr><td className="empty-state" colSpan={8}>暂无采集记录</td></tr>
          )}
        </tbody>
      </table>

      {verification.message && (
        <p className={verification.ok ? 'page-desc' : 'error-text'}>
          完整性校验：{verification.message}（检查 {verification.checked} 条）
        </p>
      )}
      {verification.issues.length > 0 && (
        <ul className="error-text">
          {verification.issues.map((issue, index) => (
            <li key={index}>
              {issue['结果编号'] || issue['清单编号'] || issue['域名'] || '数据集'}：
              {issue['字段'] ? `${issue['字段']} ` : ''}{issue['问题']}
            </li>
          ))}
        </ul>
      )}

      <footer className="page-foot">
        <span>共 {total} 条DNS解析结果</span>
        {notice && <span>{notice}</span>}
        {errorMessage && <span className="error-text">{errorMessage}</span>}
      </footer>
    </section>
  )
}
