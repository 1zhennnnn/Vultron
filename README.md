# Vultron v2 — AI-Powered Smart Contract Security Copilot

Vultron v2 transforms smart contract security analysis into a full AI copilot experience. Beyond detecting vulnerabilities, it generates exploit strategies, visualizes attack graphs, produces defense code, explains scores, and provides natural-language AI summaries — all powered by a mock AI engine with realistic outputs.

## Features

| Module | Description |
|---|---|
| **Vulnerability Detection** | Detects reentrancy, tx.origin auth bypass, unprotected selfdestruct, unsafe delegatecall, integer overflow |
| **Exploit Graph** | React Flow node graph visualizing the attack chain step-by-step |
| **Attack Generator** | Full step-by-step exploit strategy for the highest-severity vulnerability |
| **Defense Engine** | Tabbed code-level remediation with Monaco Editor examples |
| **Score Explanation** | Terminal-style breakdown of every deduction with risk context |
| **AI Copilot** | Typewriter-animated natural-language security summary |

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, TailwindCSS |
| Editor | Monaco Editor (`@monaco-editor/react`) |
| Graph | React Flow (`@xyflow/react`) |
| Charts | Recharts |
| Routing | React Router v6 |
| Backend | Node.js, Express, TypeScript (ts-node) |

## Project Structure

```
vultron/
├── frontend/     # React + Vite (port 5173)
└── backend/      # Express API (port 3001)
```

## Setup & Running Locally

### Prerequisites
- Node.js 18+
- npm 9+

### Backend

```bash
cd backend
npm install
npm run dev
```

Backend runs on: `http://localhost:3001`

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on: `http://localhost:5173`

> **Both servers must be running simultaneously.**

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/analyze` | Static analysis + vulnerability detection |
| `POST` | `/api/generate-attack` | Generate exploit strategy from vulnerabilities |
| `POST` | `/api/recommend-defense` | Generate defense code per vulnerability |
| `POST` | `/api/explain-score` | Terminal-style score breakdown |
| `POST` | `/api/ai-security-summary` | Natural language AI summary |

## Pages

| Route | Description |
|---|---|
| `/` | Landing page |
| `/dashboard` | Security overview + scan history |
| `/analyzer` | Main 5-module AI analyzer |
| `/attack-generator` | Attack simulation + exploit graph |
| `/report` | Full printable security report |

## Score Calculation

```
score = 100
  - (critical × 40)
  - (high × 25)
  - (medium × 10)
  - (low × 5)
score = max(0, score)
```

The example contract (VulnerableBank with reentrancy + tx.origin + selfdestruct) scores **0/100**.

## Screenshots

_[Add screenshots here]_

## License

MIT
