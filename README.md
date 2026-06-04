# Vultron — Solidity Smart Contract Security Analysis Platform

AI 驅動的智能合約靜態分析系統，整合 Slither 漏洞偵測、多維因果路徑推演、Hallucination 驗證與 PoC 自動生成。

---

## 環境需求

| 工具 | 版本 |
|------|------|
| Python | 3.11+ |
| Node.js | 18+ |
| Slither | 0.11.5 |
| solc | 任意版本（路徑設定見 .env） |

---

## 安裝步驟

### 後端

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# 填入 GROQ_API_KEY 和 DATABASE_URL（見下方環境變數說明）
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

```
VITE_API_URL=http://localhost:8000
```

---

## 環境變數說明

在 `backend/.env` 設定以下變數：

| 變數 | 說明 | 必填 |
|------|------|------|
| `GROQ_API_KEY` | Groq API 金鑰（[取得](https://console.groq.com)） | ✅ |
| `DATABASE_URL` | Neon PostgreSQL 連線字串（格式：`postgresql://user:pass@host/db`） | ✅ |
| `SOLC_PATH` | solc 執行檔路徑（Windows 範例：`C:/solc/solc.exe`） | 選填 |
| `FRONTEND_URL` | 前端網址，用於 CORS 設定（預設：`http://localhost:5173`） | 選填 |
| `PORT` | 後端監聽 port（預設：`8000`） | 選填 |

---

## 系統架構

```
Frontend:  React 18 + TypeScript + Vite + TailwindCSS
Backend:   Python FastAPI + WebSocket（uvicorn）
Database:  Neon PostgreSQL（SQLAlchemy async）
AI:        Groq llama-3.1-8b-instant
Analysis:  Slither 0.11.5（靜態分析引擎）
```

### 後端 API 端點

| Method | Path | 說明 |
|--------|------|------|
| POST | `/api/analyze` | 核心分析（6 階段流程） |
| POST | `/api/analyze/validate` | 輸入格式驗證 |
| POST | `/api/copilot-chat` | AI Security Copilot |
| GET | `/api/analyses` | 歷史分析列表（分頁） |
| GET | `/api/analyses/stats` | 儀表板統計數據 |
| GET | `/api/analyses/{id}` | 單次分析詳情 |
| GET | `/api/analyses/history/{name}` | 合約歷史趨勢 |
| WS | `/ws/analysis/{job_id}` | 即時進度推送 |

---

## 核心功能

- **Slither 靜態分析**：偵測 20+ 種漏洞類型（Reentrancy、tx.origin、Selfdestruct 等）
- **AI 五維因果路徑推演**：root-cause → trigger → exploit-action → cascade-effect → final-impact
- **Multi-Run Consensus**：兩次 AI 路徑生成取交集，標記高信度與低信度結論
- **Hallucination 幻覺驗證**：三層 anchor check（類型關鍵字 / 函數名 / 行號）
- **Exploitability 可利用性評分**：基於 9 種漏洞類型條件矩陣的加權評分
- **PoC 腳本自動生成**：Groq AI 生成 Hardhat 可執行攻擊測試代碼
- **合約複雜度評估**：8 維度靜態指標（LOC、函數數、繼承深度等）
- **歷史對比分析**：PostgreSQL 持久化，支援同一合約多次分析趨勢追蹤
- **REMEDIATION Tab**：每個漏洞附帶 Description / Fix（Diff 對比）/ Reference 三層修復指引

---

## Demo 合約

系統內建兩份測試合約，可在 Analyzer 頁面直接點選：

| 按鈕 | 合約 | 說明 |
|------|------|------|
| `vulnerable` | VulnerableBank | 包含 Reentrancy、tx.origin、Selfdestruct 等漏洞 |
| `safe` | SafeBank | 同功能但已套用 CEI pattern 和 ReentrancyGuard 修復 |

---

## 專案結構

```
Vultron/
├── backend/
│   ├── analyzers/
│   │   ├── slither_runner.py           # Slither 整合與漏洞映射
│   │   ├── causal_engine.py            # 因果路徑推演引擎
│   │   ├── exploitability_analyzer.py  # 可利用性評分
│   │   ├── hallucination_validator.py  # AI 幻覺驗證
│   │   ├── consensus_engine.py         # Multi-run 共識分析
│   │   ├── score_calculator.py         # 安全評分計算
│   │   ├── poc_generator.py            # PoC 腳本生成
│   │   └── complexity_analyzer.py      # 複雜度評估
│   ├── routers/
│   │   ├── analyze.py                  # 核心分析路由
│   │   └── analyses.py                 # 歷史查詢路由
│   ├── models/schemas.py               # Pydantic 資料模型
│   ├── database.py                     # SQLAlchemy 資料庫操作
│   ├── groq_client.py                  # Groq AI 調用封裝
│   ├── ws_manager.py                   # WebSocket 連線管理
│   ├── main.py                         # FastAPI 應用進入點
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── pages/                      # LandingPage、MainDashboard、DashboardPage 等
│   │   ├── components/                 # 15 個業務組件
│   │   ├── services/                   # API 調用層、useVultronAnalysis hook
│   │   ├── data/fixTemplates.ts        # 12 種漏洞修復模板
│   │   └── types/index.ts              # TypeScript 型別定義
│   └── package.json
└── README.md
```
