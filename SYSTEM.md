# Vultron — Smart Contract AI Security Analysis Platform

> 智慧創新大賽參賽作品

---

## 系統概覽

Vultron 是一套針對 Solidity 智能合約的全方位 AI 安全分析平台，結合靜態分析工具 Slither、多輪 LLM（Groq / LLaMA-3.1-8b）、Self-Consistency Consensus 機制、Hallucination 幻覺驗證，以及 WebSocket 即時進度回報，提供從漏洞偵測、攻擊模擬到修復建議的完整資安生命週期分析。

---

## 技術架構

```text
Vultron/
├── frontend/                  # React + TypeScript + Vite + Tailwind CSS
│   └── src/
│       ├── pages/             # 頁面路由
│       ├── components/        # UI 元件
│       ├── services/
│       │   ├── api.ts         # REST + WebSocket API 呼叫層
│       │   └── useVultronAnalysis.ts  # 分析狀態 Hook（含 progress）
│       ├── types/             # 共用型別定義（含 complexity、solidity_version）
│       └── i18n/              # 多語系（繁體中文 / 英文）
└── backend/                   # Python 3.11 + FastAPI + uvicorn (port 8001)
    ├── main.py                # FastAPI app 入口 + WebSocket /ws/analysis/{job_id}
    ├── ws_manager.py          # WebSocket 連線管理（active_connections + send_progress）
    ├── groq_client.py         # Groq LLM 呼叫層（7 個 AI 函數，英文指令）
    ├── database.py            # SQLAlchemy async ORM（Neon PostgreSQL）
    ├── routers/
    │   ├── analyze.py         # POST /api/analyze（6 步驟分析 + WebSocket 進度）
    │   └── analyses.py        # GET /api/analyses, /stats, /history/{name}, /{id}
    └── analyzers/
        ├── slither_runner.py  # Slither 靜態分析 + Solidity 版本自動偵測 + normalize_vuln_type
        ├── complexity_analyzer.py  # 合約複雜度靜態評估（regex，無 AI）
        ├── causal_engine.py   # 因果路徑生成（AI + 靜態規則 fallback）
        ├── exploitability_analyzer.py  # 可利用性評分（rule-based）
        ├── poc_generator.py   # PoC Hardhat 攻擊腳本生成（AI）
        ├── score_calculator.py # 安全評分計算（確定性加權）
        ├── consensus_engine.py # Multi-Run Self-Consistency（跑 2 次取交集）
        └── hallucination_validator.py  # AI 幻覺驗證（anchor 至 Slither 結果）
```

### 前端技術棧

- React 18 + TypeScript + Vite
- Tailwind CSS（sharp corners, Matrix terminal theme）
- React Flow（Causal Path Graph 節點視覺化）
- Monaco Editor（Solidity 程式碼輸入）
- i18next（繁體中文 / English）
- React Router v6
- WebSocket（瀏覽器原生 API，含 HTTP fallback）

### 後端技術棧

- Python 3.11 + FastAPI + uvicorn（port 8001）
- Slither（Python package）+ solc（SOLC_PATH 環境變數，支援 solcx 版本自動切換）
- Groq API：`llama-3.1-8b-instant`（Semaphore 並發限制 3）
- SQLAlchemy 2.0 async + asyncpg（Neon PostgreSQL）
- httpx（async HTTP 呼叫）

---

## 分析流程（Analysis Pipeline）

```text
使用者輸入 Solidity 合約
        │
        ▼
[WebSocket] 建立 /ws/analysis/{job_id} 連線
        │
        ▼
[Step 1 / 17%]  Solidity 版本自動偵測
  regex 解析 pragma solidity ^0.8.x
  → 選擇對應 solc 版本（solcx 自動安裝或 fallback 至 SOLC_PATH）
        │
        ▼
[Step 2 / 33%]  Slither 靜態分析
  ├─ 成功 → 取得漏洞清單（type 經 normalize_vuln_type 標準化）
  └─ 失敗 / 無發現 → AI 補充掃描（Groq，同樣 normalize）
        │
        ▼
[Step 3 / 50%]  Exploitability + Complexity 評估
  ├─ Exploitability：rule-based 可利用性評分（0–100）
  └─ Complexity：regex 靜態評估（LOC、函數數、外部呼叫數等 8 項指標）
        │
        ▼
[Step 4 / 67%]  AI 並行呼叫（asyncio.gather）
  ├─ 安全摘要（generate_security_summary）
  ├─ 攻擊策略（generate_attack_strategy）
  ├─ 防禦建議（generate_defense_recommendations）
  ├─ 分數說明（generate_score_explanation）
  ├─ Multi-Run Consensus（run_consensus_analysis × 2 runs）
  └─ PoC Hardhat 攻擊腳本（generate_poc_script）
        │
        ▼
[Step 5 / 83%]  Hallucination 幻覺驗證
  每個 AI 生成的 causal path node 都 anchor 至 Slither findings
  未能 anchor 的節點標記 low_confidence = True
        │
        ▼
[Step 6 / 100%]  DB 儲存 + WebSocket 完成通知
  PostgreSQL（Neon）：contracts, analyses, vulnerabilities
        │
        ▼
回傳完整 FullAnalysisResult JSON
```

---

## 核心功能

| 功能 | 說明 |
|------|------|
| **Slither 靜態分析** | 40+ 漏洞類型，type 標準化（normalize_vuln_type） |
| **Solidity 版本自動偵測** | regex 解析 pragma，solcx 自動安裝對應 solc |
| **AI 漏洞補充掃描** | Slither 失敗或零發現時，Groq LLM fallback |
| **Exploitability 評分** | rule-based 0–100 分，影響最終安全分數加權 |
| **合約複雜度評估** | 8 項靜態指標，分 LOW / MEDIUM / HIGH 三級 |
| **Multi-Run Consensus** | 同一輸入跑 2 次 AI 因果路徑，取交集為高信心結果 |
| **Hallucination 驗證** | AI 路徑節點錨定至 Slither 結果，未錨定標記警告 |
| **WebSocket 即時進度** | 6 步驟 17% → 100%，前端進度條即時更新 |
| **PoC 腳本生成** | Hardhat ethers.js v6 可執行攻擊腳本 |
| **歷史對比分析** | 同合約多次分析的分數趨勢對比 |
| **安全評分（加權）** | `100 - Σ(base_penalty × exploitability / 100)` |

---

## 安全評分規則

| 嚴重度 | Base Penalty | 風險等級 | 分數區間 |
|--------|:------------:|----------|:--------:|
| Critical | -40 × exploit% | Critical Risk | 0–19 |
| High | -25 × exploit% | High Risk | 20–39 |
| Medium | -10 × exploit% | Medium Risk | 40–59 |
| Low | -5 × exploit% | Low Risk | 60–79 |
| Info | 0 | Safe | 80–100 |

---

## API 端點

### `POST /api/analyze`

```json
Request:  {
  "code": "<Solidity source>",
  "job_id": "<uuid>",        // optional, for WebSocket progress
  "contract_name": "<name>"  // optional override
}

Response: {
  "contractName", "securityScore", "riskLevel",
  "vulnerabilities",       // full list with exploitability fields
  "summary", "attackStrategy", "defenseRecommendations", "scoreExplanation",
  "causalPaths", "criticalPathId", "pocScript",
  "slitherSuccess", "analyzedAt",
  "solidity_version", "solc_used",
  "complexity",            // { score, level, note, metrics{8 items} }
  "performance",           // { total_ms, slither_ms, groq_ms, ... }
  "hallucination",         // { validation_passed, count, rate }
  "consensus"              // { runs, successful_runs, consensus_rate, ... }
}
```

### `GET /api/analyses/{id}`

完整回傳（含 vulnerabilities list、complexity、performance）。
未儲存的欄位（summary、causalPaths、PoC）回傳空值，前端優雅降級。

### `GET /api/analyses/history/{contract_name}`

同一合約的所有分析歷史 + 分數趨勢（direction: up/down/flat）。

### `GET /api/analyses/stats`

Dashboard KPI：totalScans、avgScore、criticalRisk、topVulns、trendData。

### `WebSocket /ws/analysis/{job_id}`

即時進度推送：`{ step, total, percent, message, status }`

### `POST /api/copilot-chat`

```json
Request:  { "question", "vulnerabilities", "score" }
Response: { "answer" }
```

---

## 資料庫 Schema

```sql
contracts    (id, name, code_hash, created_at)
analyses     (id, contract_id, security_score, risk_level,
              vuln_count, critical_count, high_count,
              slither_success, total_ms, hallucination_rate,
              complexity_score, complexity_level, analyzed_at)
vulnerabilities (id, analysis_id, vuln_id, type, function,
                 severity, description, line_number,
                 exploitability_score, exploitability_level)
```

---

## 頁面結構

| 路由 | 頁面 | 說明 |
|------|------|------|
| `/` | LandingPage | 產品介紹、Matrix Canvas 動畫 |
| `/dashboard` | DashboardPage | 歷史掃描 KPI、圖表、Recent Scans 表格 |
| `/analyzer` | MainDashboard | 核心分析頁（Monaco Editor + WebSocket 進度條 + 所有分析面板） |
| `/report` | ReportPage | 完整報告（`?id=` 從 DB 載入；無參數從 localStorage） |

---

## 環境變數

```env
# backend/.env
GROQ_API_KEY=<your-key>
PORT=8001
FRONTEND_URL=http://localhost:5174
DATABASE_URL=postgresql://<user>:<pass>@<host>/<db>?sslmode=require
SOLC_PATH=<path-to-solc-binary>  # fallback compiler

# frontend/.env.local
VITE_API_URL=http://localhost:8001
```

---

## 啟動方式

```bash
# 後端
cd backend
pip install -r requirements.txt
python main.py

# 前端
cd frontend
npm install
npm run dev
```

---

## Demo 合約清單

| 合約 | 說明 | 預期結果 |
|------|------|---------|
| `VulnerableBank` | Reentrancy + tx.origin + Selfdestruct | Critical Risk，score ≈ 0 |
| `SafeBank` | 手寫 nonReentrant + onlyOwner，無外部 import | Safe，score ≈ 100 |
