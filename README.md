# 分布式网页抓取调度平台

面向分布式网页抓取任务调度、节点协同、请求分配、反爬策略编排、数据校验入库与抓取质量大盘的采集工程管理平台。

这是一个前后端分离的管理平台：前端 React + Vite + TypeScript，后端 FastAPI（Python）。
两边各自独立启动，前端 dev server 已关掉自动打开页面，启动后按终端打印的地址手工打开。

## 目录结构

```text
.
├── frontend/                 React + Vite + TypeScript 前端
│   ├── src/views/            每个业务模块一个页面
│   ├── src/api/              统一请求封装
│   ├── src/stores/           会话与筛选状态
│   └── vite.config.ts        dev server 配置（open: false）
├── backend/                  FastAPI（Python） 后端
│   ├── app/routers/          每个业务模块一组接口
│   ├── app/services/         业务规则与状态流转
│   └── app/store.py          内存数据仓库与示例数据
├── .gitignore
└── docker-compose.yml
```

## 启动

### 后端

```bash
cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh
```

健康检查：`curl http://127.0.0.1:8000/api/health`

### 前端

```bash
cd frontend
npm install
npm run dev
```

前端默认监听 `http://127.0.0.1:5173/`，dev server 不会自动打开浏览器，
需要自己访问。`/api` 由 vite 代理到后端 `http://127.0.0.1:8000`。

## 业务模块

| 模块 | 目录 | 业务对象 | 主要字段 |
| --- | --- | --- | --- |
| 采集节点 | `worker` | 工作节点 | 节点编号、主机地址、并发槽位数 |
| 请求分配 | `dispatch` | 分配策略 | 策略编号、目标域名、分配算法 |
| 抓取作业 | `crawljob` | 作业定义 | 作业编号、目标站点、起始URL |
| URL过滤 | `urlfilter` | 过滤规则 | 规则编号、包含模式、排除模式 |
| DNS解析 | `dnsresolver` | 解析配置 | 配置编号、域名模式、DNS服务器 |
| DNS解析结果 | `dnsresult` | 解析结果追踪 | 结果编号、域名、配置版本、地址来源、使用DNS服务器、故障转移路径、批次号 |
| 内容提取 | `contentextract` | 提取器 | 提取器编号、内容类型、正文选择器 |
| 存储策略 | `storagestrategy` | 存储方案 | 方案编号、存储类型、连接参数 |
| 渲染任务 | `rendertask` | 渲染作业 | 作业编号、目标URL、浏览器版本 |
| 采集质量 | `qualityreport` | 质量报告 | 报告编号、作业编号、总URL数 |
| 带宽控制 | `bandwidth` | 带宽策略 | 策略编号、节点标识、下载带宽上限 |
| 重试队列 | `retryqueue` | 重试条目 | 条目编号、失败URL、失败原因码 |
| 翻页管理 | `pagemarker` | 翻页规则 | 规则编号、目标站点、翻页类型 |
| 增量标记 | `incrementmark` | 增量水位 | 水位编号、目标源、增量字段名 |
| 配置同步 | `configsync` | 同步任务 | 任务编号、源节点、目标节点 |
| 采集API | `scrapeapi` | API定义 | API编号、API名称、请求路径 |
| 数据抽样 | `datasample` | 抽样方案 | 方案编号、数据源、抽样方式 |
| 采集告警 | `alertpolicy` | 告警策略 | 策略编号、监控指标、触发条件 |

## DNS解析结果追踪

`dnsresolver` 维护解析配置（域名模式、DNS服务器、缓存TTL、主备地址、配置版本、
重试上限），`dnsresult` 负责把每次解析落成可追溯、可校验的结果数据集。

### 接口

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/dnsresult` | 解析结果列表（按结果编号/域名/状态过滤） |
| GET | `/api/dnsresult/{id}` | 单条结果明细（含证据摘要） |
| POST | `/api/dnsresult/resolve` | 解析域名并生成结果 |
| GET | `/api/dnsresult/verify` | 校验数据集完整性，可带 `entry_id` 单条校验 |
| POST | `/api/dnsresult/consume` | 执行协同侧消费成功的解析结果 |
| GET | `/api/dnsresult/execution-manifest` | 执行协同清单 |
| GET | `/api/dnsresult/crawl-records` | 采集记录（失败码与原因写回） |
| GET | `/api/dnsresult/caches` / `batches` | 缓存快照与批次 |
| POST | `/api/dnsresolver/{id}/versions` | 发布配置新版本并失效旧缓存 |

`resolve` 支持 `域名`、`作业编号`、`采集URL`、`尝试次数`、`刷新`、
`配置版本快照`、`主解析状态`、`故障转移状态` 等字段。

### 规则

- 缓存复用必须同时满足：TTL 未过期、配置版本一致、IPv6 优先级一致；过期缓存
  不会把旧配置版本的地址带回来。
- 主解析超时但缓存仍有剩余 TTL 时，与故障转移一并进入同一个证据对象裁决，
  批次边界冲突统一裁决为「缓存优先」，不会出现两个地址来源。
- 同一域名与配置只保留一个生效批次，新解析会把旧生效批次标记为「已合并」。
- 配置切换期间旧请求（`配置版本快照` 与当前版本不一致）返回
  `CONFIG_VERSION_CHANGED`，不回写新版本地址；主备都失败且达到重试上限返回
  `RETRY_EXHAUSTED`。
- 同一份解析结果重复处理只返回既有记录，不重复计数；同一域名的并发解析由
  域名级锁串行化并复用先到结果，结果不分叉。
- 执行协同只消费成功的解析结果；失败结果把失败码与原因写回采集记录，
  清单标记为「不可消费」。
- `verify` 校验追溯字段、批次唯一性、缓存引用一致性、证据摘要与结果一致性、
  消费链路，并返回问题清单。

## 约定

- 每个模块的前端页面在 `frontend/src/views/<模块>/index.vue`，后端接口在
  `backend/app/routers/<模块>.py`，业务规则在 `backend/app/services/<模块>.py`。
- 列表接口统一返回 `{ items, total, page, size }`，动作接口统一返回 `{ ok, message }`。
- 状态流转只允许在 `app/services` 里改，路由层不做业务判断。

领域：数据工程
子方向：数据采集、爬虫与RPA
