# Vultron v3 — AI-Powered Smart Contract Security Platform

Vultron v3 是一套智能合約安全分析平台，整合 Slither 靜態分析與 Groq AI（llama-3.3-70b-versatile），提供漏洞偵測、AI 攻擊路徑推演、PoC 腳本生成、防禦建議與互動式 Copilot，所有 AI 輸出以繁體中文呈現。

## 功能模組

| 模組 | 說明 |
|---|---|
| **Slither 靜態分析** | 真實執行 Slither，偵測 reentrancy、tx.origin、selfdestruct、delegatecall、integer overflow 等 27 種漏洞類型 |
| **確定性安全評分** | 依漏洞嚴重度計算 0–100 分（critical -40、high -25、medium -10、low -5） |
| **AI 安全摘要** | Groq AI 針對合約內容與漏洞生成繁體中文摘要 |
| **攻擊流程圖** | React Flow 有向圖視覺化逐步攻擊鏈 |
| **AI 攻擊路徑推演** | Groq AI 生成結構化因果節點圖（root-cause → trigger → exploit → impact） |
| **攻擊模擬** | 動畫逐步播放攻擊策略，含進度條與模擬控制 |
| **PoC 攻擊腳本** | Groq AI 針對合約漏洞生成 Hardhat 測試腳本（ethers.js v6） |
| **防禦建議** | AI 提供每個漏洞的修復策略與 Solidity 程式碼範例 |
| **漏洞知識庫** | 5 種漏洞類型的靜態教學（SWC ID、真實案例、攻擊模式、防禦策略） |
| **AI Copilot** | 互動問答，依合約分析結果回答資安問題（繁體中文） |
| **安全報告** | 可匯出 JSON / 複製 Markdown 的完整分析報告 |

## 技術堆疊

| 層級 | 技術 |
|---|---|
| Frontend | React 18、TypeScript、Vite、TailwindCSS |
| 程式碼編輯器 | Monaco Editor (`@monaco-editor/react`) |
| 攻擊圖 | React Flow (`@xyflow/react`) |
| 路由 | React Router v6 |
| 國際化 | react-i18next（中文 / 英文） |
| Backend | Node.js、Express、TypeScript（ts-node） |
| 靜態分析 | Slither（Python）、solc |
| AI 引擎 | Groq API — llama-3.3-70b-versatile |

## 專案結構

```
vultron/
├── frontend/                  # React + Vite（port 5173）
│   └── src/
│       ├── pages/             # AnalyzerPage、AttackGeneratorPage、ReportPage...
│       ├── components/        # CausalPathGraph、ExploitGraph、SecurityCopilotPanel...
│       ├── services/api.ts    # 前端 API 呼叫
│       └── types/index.ts     # 共用型別定義
└── backend/                   # Express API（port 3001）
    └── src/
        ├── analyzer/
        │   ├── slitherRunner.ts    # Slither 執行與結果解析
        │   ├── causalEngine.ts     # 攻擊路徑推演（靜態規則 + AI）
        │   ├── claudeClient.ts     # Groq AI 呼叫（所有 AI 功能）
        │   ├── pocGenerator.ts     # PoC Hardhat 腳本生成
        │   └── scoreCalculator.ts  # 確定性評分計算
        └── controllers/
            └── analyzeController.ts
```

## 本機啟動

### 環境需求
- Node.js 18+
- Python 3.11+
- Slither（`pip install slither-analyzer`）
- solc（放置於 `C:/Users/zhenn/solc.exe`，Windows 本機限定）

### 環境變數

**backend/.env**
```
PORT=3001
GROQ_API_KEY=your_groq_api_key
NODE_ENV=development
FRONTEND_URL=http://localhost:5173
```

**frontend/.env.local**（本機開發）
```
VITE_API_URL=http://localhost:3001
```

### 啟動 Backend

```bash
cd backend
npm install
npm run dev
```

Backend 執行於：`http://localhost:3001`

### 啟動 Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend 執行於：`http://localhost:5173`

> **兩個伺服器必須同時執行。**

## API 端點

| Method | Path | 說明 |
|---|---|---|
| `POST` | `/api/analyze` | 完整合約分析（Slither + AI） |
| `POST` | `/api/copilot` | AI Copilot 問答 |

## 頁面結構

| 路由 | 說明 |
|---|---|
| `/` | 首頁 Landing Page |
| `/dashboard` | 資安總覽與掃描歷史 |
| `/analyzer` | 主分析器（漏洞偵測、評分、AI 分析、Copilot） |
| `/attack-generator` | 攻擊模擬（攻擊策略動畫、因果路徑圖、PoC 腳本） |
| `/report` | 完整安全報告（漏洞表格、防禦建議、AI 摘要、匯出） |

## 評分公式

```
score = 100 - (critical × 40) - (high × 25) - (medium × 10) - (low × 5)
score = max(0, score)
```

範例合約 VulnerableBank（reentrancy + tx.origin + selfdestruct）評分為 **0/100（Critical Risk）**。

## 重要限制

- Slither 目前僅在本機 Windows 環境可執行（solc 路徑硬寫）
- Groq 免費帳號每日 Token 上限 100,000，超過後分析功能暫停至次日 UTC 00:00 重置
- PoC 腳本為 AI 生成，未經執行驗證，僅供安全研究參考

## License

MIT
