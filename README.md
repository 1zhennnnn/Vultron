# Vultron — Solidity Smart Contract Security Analysis Platform

AI 驅動的智能合約安全分析平台，整合 Slither 靜態分析、Multi-Run Consensus 機制、Hallucination 幻覺驗證、因果路徑推演與 PoC 腳本自動生成，提供從漏洞偵測到攻擊模擬的完整資安分析流程。

---

## 功能特色

| 功能 | 說明 |
|------|------|
| **Slither 靜態分析** | 40+ 漏洞類型，type 經 `normalize_vuln_type` 標準化，附 SWC / MITRE CWE ID |
| **Solidity 版本自動偵測** | regex 解析 `pragma solidity`，solcx 自動安裝對應 solc |
| **AI 漏洞補充掃描** | Slither 失敗或零發現時，Groq LLM fallback |
| **Exploitability 評分** | 9 種漏洞類型條件矩陣，rule-based 0–100 分 |
| **合約複雜度評估** | 8 維度靜態指標（LOC、函數數、繼承深度等），分 LOW / MEDIUM / HIGH |
| **Multi-Run Consensus** | 同一輸入跑 2 次 AI 因果路徑，取交集為高信心結果，單次僅出現標記 low_confidence |
| **Hallucination 驗證** | AI 路徑節點三層 anchor check，未錨定率超過 0.30 標記失敗 |
| **PoC 腳本生成** | Groq AI 生成 Hardhat ethers.js v6 可執行攻擊腳本 |
| **WebSocket 即時進度** | 6 步驟 17% → 100%，前端進度條即時更新 |
| **REMEDIATION Tab** | 每個漏洞附帶 Description / Fix Diff / Reference 三層修復指引 |
| **歷史對比分析** | PostgreSQL 持久化，同一合約多次分析的分數趨勢 |
| **JWT 認證系統** | 帳號註冊 / 登入 / 修改密碼，每筆分析紀錄綁定使用者 |

---

## 技術棧

```
Frontend:  React 18 + TypeScript + Vite + Tailwind CSS
Backend:   Python 3.11 + FastAPI + uvicorn
Database:  Neon PostgreSQL (SQLAlchemy 2.0 async + asyncpg)
AI:        Groq llama-3.1-8b-instant
Analysis:  Slither 0.11.5 + solcx
Auth:      python-jose (JWT) + passlib (bcrypt)
```

---

## 環境需求

| 工具 | 版本 |
|------|------|
| Python | 3.11+ |
| Node.js | 18+ |
| Slither | 0.11.5（`pip install slither-analyzer==0.11.5`） |
| solc | 由 solcx 自動管理，或手動設定 `SOLC_PATH` |

---

## 本機啟動

### 後端

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# 填入 GROQ_API_KEY 和 DATABASE_URL（見下方說明）
uvicorn main:app --reload --port 8000
```

### 前端

```bash
cd frontend
npm install
npm run dev
# 預設開在 http://localhost:5173
```

前端預設連接 `http://localhost:8000`，可在 `frontend/.env.local` 覆蓋：

```env
VITE_API_URL=http://localhost:8000
```

---

## 環境變數

`backend/.env`（從 `.env.example` 複製）：

| 變數 | 說明 | 必填 |
|------|------|:----:|
| `GROQ_API_KEY` | Groq API 金鑰，取得：https://console.groq.com | ✅ |
| `DATABASE_URL` | Neon PostgreSQL 連線字串，格式：`postgresql+asyncpg://user:pass@host/db` | ✅ |
| `JWT_SECRET` | JWT 簽名密鑰（請換成長隨機字串） | ✅ |
| `SOLC_PATH` | solc 執行檔路徑（本機 Windows 備用，solcx 優先） | 選填 |
| `FRONTEND_URL` | 前端網址，用於 CORS 設定（預設：`http://localhost:5173`） | 選填 |
| `PORT` | 後端監聽 port（預設：`8000`） | 選填 |

---

## API 端點

| Method | Path | 說明 |
|--------|------|------|
| POST | `/api/analyze` | 核心分析（6 階段，含 WebSocket 進度） |
| POST | `/api/copilot-chat` | AI Security Copilot 問答 |
| GET | `/api/analyses` | 歷史分析列表 |
| GET | `/api/analyses/stats` | Dashboard KPI |
| GET | `/api/analyses/{id}` | 單次分析詳情 |
| GET | `/api/analyses/history/{name}` | 合約分數趨勢 |
| WS | `/ws/analysis/{job_id}` | 即時進度推送 |
| POST | `/api/auth/register` | 帳號註冊 |
| POST | `/api/auth/login` | 帳號登入 |
| GET | `/api/auth/me` | 取得目前使用者資訊 |
| PATCH | `/api/auth/password` | 修改密碼 |

---

## 分析流程

```
使用者輸入 Solidity 合約
    │
    ▼
[Step 1 / 17%]  Solidity 版本自動偵測
[Step 2 / 33%]  Slither 靜態分析（失敗時 Groq fallback）
[Step 3 / 50%]  Exploitability + Complexity 評估
[Step 4 / 67%]  AI 並行呼叫（摘要 / 攻擊策略 / 防禦建議 / 評分說明 / Consensus × 2 / PoC）
[Step 5 / 83%]  Hallucination 幻覺驗證（threshold 0.30）
[Step 6 / 100%] PostgreSQL 儲存 + WebSocket 完成通知
    │
    ▼
完整 FullAnalysisResult JSON
```

---

## 安全評分規則

| 嚴重度 | Base Penalty | 分數區間 | 風險等級 |
|--------|:------------:|:--------:|----------|
| Critical | -40 × exploit% | 0–19 | Critical Risk |
| High | -25 × exploit% | 20–39 | High Risk |
| Medium | -10 × exploit% | 40–59 | Medium Risk |
| Low | -5 × exploit% | 60–79 | Low Risk |
| Info | 0 | 80–100 | Safe |

最終分數：`100 - Σ(base_penalty × exploitability_score / 100)`，下限 0。

---

## 頁面結構

| 路由 | 頁面 | 說明 |
|------|------|------|
| `/` | LandingPage | 產品介紹，Matrix canvas 動畫 |
| `/login` | AuthPage | 帳號登入 / 註冊 |
| `/dashboard` | DashboardPage | 歷史掃描 KPI、圖表、Recent Scans |
| `/analyzer` | MainDashboard | 核心分析頁（Monaco Editor + WebSocket 進度條） |
| `/report` | ReportPage | 完整報告（`?id=` 從 DB 載入，無參數從 localStorage） |
| `/vulnerabilities` | VulnerabilitiesPage | 漏洞總覽 |
| `/account` | AccountPage | 帳號設定、修改密碼 |

---

## 專案結構

```
Vultron/
├── backend/
│   ├── analyzers/
│   │   ├── slither_runner.py           # Slither 整合與漏洞正規化
│   │   ├── causal_engine.py            # AI 五維因果路徑推演
│   │   ├── consensus_engine.py         # Multi-run Self-Consistency
│   │   ├── exploitability_analyzer.py  # 可利用性條件矩陣評分
│   │   ├── hallucination_validator.py  # AI 幻覺驗證（threshold 0.30）
│   │   ├── poc_generator.py            # Hardhat PoC 腳本生成
│   │   ├── score_calculator.py         # 加權安全評分
│   │   └── complexity_analyzer.py      # 8 維度靜態複雜度評估
│   ├── routers/
│   │   ├── analyze.py                  # 核心分析路由（6 步驟）
│   │   ├── analyses.py                 # 歷史查詢路由
│   │   └── auth.py                     # JWT 認證路由
│   ├── models/schemas.py               # Pydantic 資料模型
│   ├── database.py                     # SQLAlchemy async ORM
│   ├── groq_client.py                  # Groq AI 調用封裝
│   ├── ws_manager.py                   # WebSocket 連線管理
│   ├── main.py                         # FastAPI 應用進入點
│   ├── test_contracts/                 # 測試用 Solidity 合約
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── pages/                      # 7 個頁面（含 AuthPage、AccountPage）
│       ├── components/                 # 15 個業務元件
│       ├── services/
│       │   ├── api.ts                  # REST / WebSocket API 層
│       │   └── useVultronAnalysis.ts   # 分析狀態 Hook
│       ├── data/fixTemplates.ts        # 12 種漏洞修復模板
│       ├── i18n/                       # 繁體中文 / English
│       └── types/index.ts              # TypeScript 型別定義
├── SYSTEM.md                           # 詳細技術文件
└── README.md
```

---

## Demo 合約

系統內建測試合約，可在 Analyzer 頁面直接點選載入：

| 按鈕 | 說明 | 預期結果 |
|------|------|---------|
| `vulnerable` | VulnerableBank — Reentrancy + tx.origin + Selfdestruct | Critical Risk，分數 ≈ 0 |
| `safe` | SafeBank — CEI pattern + ReentrancyGuard，無外部 import | Safe，分數 ≈ 100 |
