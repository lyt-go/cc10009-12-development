import { useEffect, useState } from 'react'

import { fetchJson } from '@/api/client'

type Overview = {
  cards: { label: string; value: number }[]
  modules: { name: string; created: number; pending: number; abnormal: number }[]
}

const fallbackCards = [{"label": "业务模块", "value": 0}, {"label": "今日新增", "value": 0}]
const fallbackModules = [{"name": "采集节点", "created": 0, "pending": 0, "abnormal": 0}, {"name": "请求分配", "created": 0, "pending": 0, "abnormal": 0}, {"name": "抓取作业", "created": 0, "pending": 0, "abnormal": 0}, {"name": "URL过滤", "created": 0, "pending": 0, "abnormal": 0}, {"name": "DNS解析", "created": 0, "pending": 0, "abnormal": 0}, {"name": "DNS解析结果", "created": 0, "pending": 0, "abnormal": 0}, {"name": "内容提取", "created": 0, "pending": 0, "abnormal": 0}, {"name": "存储策略", "created": 0, "pending": 0, "abnormal": 0}, {"name": "渲染任务", "created": 0, "pending": 0, "abnormal": 0}, {"name": "采集质量", "created": 0, "pending": 0, "abnormal": 0}, {"name": "带宽控制", "created": 0, "pending": 0, "abnormal": 0}, {"name": "重试队列", "created": 0, "pending": 0, "abnormal": 0}, {"name": "翻页管理", "created": 0, "pending": 0, "abnormal": 0}, {"name": "增量标记", "created": 0, "pending": 0, "abnormal": 0}, {"name": "配置同步", "created": 0, "pending": 0, "abnormal": 0}, {"name": "采集API", "created": 0, "pending": 0, "abnormal": 0}, {"name": "数据抽样", "created": 0, "pending": 0, "abnormal": 0}, {"name": "采集告警", "created": 0, "pending": 0, "abnormal": 0}]

export default function Overview() {
  const [cards, setCards] = useState<Overview['cards']>(fallbackCards)
  const [moduleRows, setModuleRows] = useState<Overview['modules']>(fallbackModules)

  useEffect(() => {
    fetchJson<Overview>('/api/overview')
      .then((payload) => {
        setCards(payload.cards)
        setModuleRows(payload.modules)
      })
      .catch(() => undefined)
  }, [])

  return (
    <section className="page">
      <header className="page-head">
        <div>
          <h2>运营概览</h2>
          <p className="page-desc">汇总各业务模块的关键指标，先看总量再看异常。</p>
        </div>
      </header>
      <div className="stat-row">
        {cards.map((card) => (
          <article key={card.label} className="stat-card">
            <span className="stat-label">{card.label}</span>
            <strong className="stat-value">{card.value}</strong>
          </article>
        ))}
      </div>
      <table className="data-table">
        <thead>
          <tr><th>业务模块</th><th>今日新增</th><th>待处理</th><th>异常量</th></tr>
        </thead>
        <tbody>
          {moduleRows.map((row) => (
            <tr key={row.name}>
              <td>{row.name}</td>
              <td>{row.created}</td>
              <td>{row.pending}</td>
              <td>{row.abnormal}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
