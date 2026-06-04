import { useState } from 'react';
import { ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import Sidebar from '../components/Sidebar';

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff4444',
  HIGH:     '#ffaa00',
  MEDIUM:   '#00ff41',
  LOW:      '#555555',
};

const vulnData = [
  {
    id: 'SWC-107',
    name: 'REENTRANCY',
    severity: 'CRITICAL',
    desc: 'External call made before state update allows recursive re-entry',
    attack: '攻擊者部署含 fallback/receive 的惡意合約，在目標合約轉帳後、更新餘額前遞迴重入提款函數，反覆抽乾合約 ETH',
    fix: '遵循 CEI 模式（Checks → Effects → Interactions）：先更新狀態，再執行外部呼叫。或套用 nonReentrant modifier 阻斷遞迴',
    oz: 'ReentrancyGuard',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard',
  },
  {
    id: 'SWC-115',
    name: 'TX.ORIGIN AUTH',
    severity: 'HIGH',
    desc: 'tx.origin used for authentication instead of msg.sender',
    attack: '攻擊者建立釣魚合約，誘導合法 owner 呼叫它。由於 tx.origin 永遠指向最初發起者，釣魚合約可假冒 owner 身份呼叫任意受保護函數',
    fix: '永遠使用 msg.sender 進行身份驗證，不要使用 tx.origin。若需要區分合約/EOA 呼叫，使用 msg.sender != tx.origin 條件判斷',
    oz: 'Ownable',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/access#Ownable',
  },
  {
    id: 'SWC-106',
    name: 'UNPROTECTED SELFDESTRUCT',
    severity: 'CRITICAL',
    desc: 'selfdestruct() callable by any address — permanently destroys contract',
    attack: '攻擊者直接呼叫包含 selfdestruct 的函數（無存取控制保護），合約所有 ETH 轉移至攻擊者地址，合約 bytecode 從鏈上永久刪除',
    fix: '在含 selfdestruct 的函數加上 onlyOwner 或 onlyAdmin 修飾器，確保只有授權地址可觸發。建議重新評估是否真的需要 selfdestruct',
    oz: 'Ownable',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/access#Ownable',
  },
  {
    id: 'SWC-112',
    name: 'UNSAFE DELEGATECALL',
    severity: 'CRITICAL',
    desc: 'delegatecall to attacker-controlled address executes in victim storage context',
    attack: '攻擊者提供惡意 implementation 合約地址，透過 delegatecall 在受害者合約的 storage context 中執行任意程式碼，覆寫 slot 0（通常是 owner），取得完整控制權',
    fix: '只對受信任的固定地址執行 delegatecall，絕不使用用戶輸入的地址。若需要可升級架構，使用 OpenZeppelin Transparent Proxy 或 UUPS 模式',
    oz: 'UUPSUpgradeable',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable',
  },
  {
    id: 'SWC-101',
    name: 'INTEGER OVERFLOW',
    severity: 'HIGH',
    desc: 'Arithmetic wraps around uint256 boundary without SafeMath protection',
    attack: '攻擊者傳入接近 uint256 最大值（2²⁵⁶−1）的數值，加法溢位歸零或乘法溢位至極小值，使餘額或計數器出現異常，進而提取遠超存入量的資金',
    fix: 'Solidity 0.8.x 以上預設啟用 overflow 檢查，會自動 revert。舊版本需使用 OpenZeppelin SafeMath。避免使用 unchecked{} 區塊除非有明確理由',
    oz: 'SafeMath（Solidity <0.8）',
    ozLink: 'https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath',
  },
  {
    id: 'SWC-105',
    name: 'ACCESS CONTROL',
    severity: 'HIGH',
    desc: 'Privileged functions lack ownership or role-based access restrictions',
    attack: '攻擊者直接呼叫應受保護的管理函數（如 transferOwnership、setPrice、mint），由於缺乏存取控制，任何 EOA 或合約均可執行，導致合約參數被竄改或資產被盜',
    fix: '使用 Ownable 限制單一 owner 存取，或使用 AccessControl 實作細粒度角色管理（如 ADMIN_ROLE、MINTER_ROLE）',
    oz: 'Ownable / AccessControl',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/access',
  },
  {
    id: 'SWC-104',
    name: 'UNCHECKED CALL',
    severity: 'MEDIUM',
    desc: 'Return value of low-level call() not checked — silent failures ignored',
    attack: '低階 call() 失敗時僅回傳 false，不自動 revert。若程式碼未檢查回傳值，合約會繼續執行，假設轉帳成功但資金實際未動，造成狀態與餘額不一致',
    fix: '改用 transfer() 或 send() + require 檢查，或使用 Address.sendValue()（自動 revert on failure）。若必須使用 call()，務必 require(success, "transfer failed")',
    oz: 'Address.sendValue',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/utils#Address-sendValue-address-payable-uint256-',
  },
  {
    id: 'SWC-116',
    name: 'TIMESTAMP DEPENDENCE',
    severity: 'MEDIUM',
    desc: 'block.timestamp used for randomness or time-critical logic — miner manipulable',
    attack: '礦工可在 ±15 秒範圍內調整 block.timestamp，影響依賴時間的抽獎、拍賣截止、解鎖條件等邏輯，讓攻擊者（或礦工本身）在有利時間點觸發合約',
    fix: '不要用 block.timestamp 作為亂數來源。時間鎖邏輯接受小幅度誤差（建議 ≥15 分鐘的時間窗口）。亂數需求使用 Chainlink VRF',
    oz: 'VRFConsumerBaseV2（Chainlink）',
    ozLink: 'https://docs.chain.link/vrf/v2/introduction',
  },
  {
    id: 'SWC-128',
    name: 'DENIAL OF SERVICE',
    severity: 'HIGH',
    desc: 'Unbounded loop or push-payment pattern makes function permanently uncallable',
    attack: '攻擊者不斷向合約新增資料（如 push 到 address[]），使迭代此陣列的函數 gas 耗用超出區塊上限（~30M gas），導致所有後續呼叫因 out-of-gas 而永久失敗',
    fix: '避免迭代無界陣列。使用 pull-payment 模式（讓使用者自行提款）取代 push。若必須迭代，加入分批處理（pagination）機制',
    oz: 'PullPayment',
    ozLink: 'https://docs.openzeppelin.com/contracts/5.x/api/security#PullPayment',
  },
  {
    id: 'SWC-114',
    name: 'FRONT RUNNING',
    severity: 'MEDIUM',
    desc: 'Pending transactions visible in mempool — attackers can insert higher-gas txs first',
    attack: '攻擊者監控 mempool 中的高價值待確認交易，複製相同呼叫並提高 gas price，讓礦工優先打包其交易。常見於 DEX 套利、搶先購買限定 NFT、操縱預言機報價',
    fix: '使用 commit-reveal 模式（先提交 hash，再揭露資料）。對交易設定 slippage tolerance 或 deadline 時間戳。敏感操作可使用 Flashbots private relay 繞過公開 mempool',
    oz: 'N/A — 架構層解決方案',
    ozLink: 'https://docs.flashbots.net',
  },
];

function VulnCard({ v }: { v: typeof vulnData[number] }) {
  const [open, setOpen] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [activeTab, setActiveTab] = useState<'description' | 'fix' | 'reference'>('description');
  const color = SEV_COLOR[v.severity] ?? '#555555';

  return (
    <div
      onClick={() => setOpen(o => !o)}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        border: `1px solid ${hovered ? color : '#222222'}`,
        borderLeft: `3px solid ${color}`,
        background: '#0d0d0d',
        cursor: 'pointer',
        transition: 'border-color 0.12s ease',
        fontFamily: "'Courier New', monospace",
      }}
    >
      {/* Card header */}
      <div className="flex items-start justify-between p-4">
        <div className="flex flex-col gap-1.5 flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span style={{
              fontSize: 10, fontWeight: 700, letterSpacing: '0.08em',
              color, border: `1px solid ${color}`, padding: '1px 6px',
              flexShrink: 0,
            }}>
              {v.severity}
            </span>
            <span style={{ fontSize: 11, color: '#888888', flexShrink: 0 }}>{v.id}</span>
          </div>
          <p style={{ fontSize: 13, fontWeight: 700, color: '#e0e0e0', letterSpacing: '0.06em' }}>
            {v.name}
          </p>
          <p style={{ fontSize: 11, color: '#555555', lineHeight: 1.5 }}>{v.desc}</p>
        </div>
        <span style={{ fontSize: 9, fontFamily: 'monospace', fontWeight: 700, color: open ? '#00ff41' : '#555555', flexShrink: 0, marginLeft: 12, marginTop: 2 }}>
          {open ? '▼ COLLAPSE' : '▶ EXPAND'}
        </span>
      </div>

      {/* Expandable body */}
      {open && (
        <div
          style={{ borderTop: '1px solid #1a1a1a', paddingBottom: 14, display: 'flex', flexDirection: 'column' }}
          onClick={e => e.stopPropagation()}
        >
          {/* Tabs */}
          <div className="flex border-b border-[#1a1a1a] mb-3">
            {(['description', 'fix', 'reference'] as const).map(tab => (
              <button
                key={tab}
                onClick={e => { e.stopPropagation(); setActiveTab(tab); }}
                style={{
                  padding: '7px 14px', fontSize: 9, fontWeight: 700,
                  letterSpacing: '0.12em', fontFamily: 'monospace',
                  textTransform: 'uppercase', border: 'none',
                  background: activeTab === tab ? 'rgba(0,255,65,0.07)' : 'transparent',
                  color: activeTab === tab ? '#00ff41' : '#555555',
                  borderBottom: activeTab === tab ? '2px solid #00ff41' : '2px solid transparent',
                  cursor: 'pointer',
                }}
              >
                {tab === 'description' ? 'DESCRIPTION' : tab === 'fix' ? 'FIX' : 'REFERENCE'}
              </button>
            ))}
          </div>

          <div style={{ padding: '0 16px' }}>
            {activeTab === 'description' && (
              <p style={{ fontSize: 11, color: '#888888', lineHeight: 1.7 }}>{v.attack}</p>
            )}
            {activeTab === 'fix' && (
              <p style={{ fontSize: 11, color: '#888888', lineHeight: 1.7 }}>{v.fix}</p>
            )}
            {activeTab === 'reference' && (
              <div className="flex items-center gap-2">
                <p style={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.1em', color: '#555555' }}>
                  &gt; OZ_REF:
                </p>
                <a
                  href={v.ozLink}
                  target="_blank"
                  rel="noopener noreferrer"
                  onClick={e => e.stopPropagation()}
                  style={{ fontSize: 11, color: '#00ff41', display: 'flex', alignItems: 'center', gap: 4 }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#00cc33')}
                  onMouseLeave={e => (e.currentTarget.style.color = '#00ff41')}
                >
                  {v.oz} <ExternalLink size={10} />
                </a>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function VulnerabilitiesPage() {
  const [filter, setFilter] = useState<string>('ALL');
  const criticalCount = vulnData.filter(v => v.severity === 'CRITICAL').length;
  const highCount     = vulnData.filter(v => v.severity === 'HIGH').length;
  const mediumCount   = vulnData.filter(v => v.severity === 'MEDIUM').length;
  const filtered      = filter === 'ALL' ? vulnData : vulnData.filter(v => v.severity === filter);

  const FILTER_COLOR: Record<string, string> = {
    CRITICAL: '#ff4444', HIGH: '#ffaa00', MEDIUM: '#00ff41', ALL: '#00ff41',
  };

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#000000', fontFamily: "'Courier New', monospace" }}>
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-5 flex flex-col gap-4">

        {/* Header */}
        <div className="flex items-center justify-between border-b pb-3" style={{ borderColor: '#222222' }}>
          <div>
            <p style={{ color: '#00ff41', fontSize: 13, fontWeight: 700, letterSpacing: '0.1em' }}>&gt; VULN_KNOWLEDGE_BASE</p>
            <p style={{ color: '#555555', fontSize: 11, marginTop: 2 }}>// {filtered.length} of {vulnData.length} vulnerability patterns — click card to expand</p>
          </div>
          <div className="flex items-center gap-2">
            {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'] as const).map(f => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                style={{
                  padding: '4px 12px', fontSize: 10, fontWeight: 700,
                  letterSpacing: '0.08em', fontFamily: 'monospace',
                  cursor: 'pointer', border: `1px solid ${filter === f ? FILTER_COLOR[f] : '#333333'}`,
                  background: filter === f ? `${FILTER_COLOR[f]}18` : 'transparent',
                  color: filter === f ? FILTER_COLOR[f] : '#555555',
                  transition: 'all 0.1s',
                }}
              >
                {f}
              </button>
            ))}
            <div style={{ width: 1, height: 20, background: '#222222', margin: '0 8px' }} />
            {[
              { label: 'CRITICAL', count: criticalCount, color: '#ff4444' },
              { label: 'HIGH',     count: highCount,     color: '#ffaa00' },
              { label: 'MEDIUM',   count: mediumCount,   color: '#00ff41' },
            ].map(({ label, count, color }) => (
              <div key={label} className="flex items-center gap-1">
                <span style={{ fontSize: 9, color: '#444444' }}>{label}</span>
                <span style={{ fontSize: 14, fontWeight: 700, color, fontFamily: 'monospace' }}>{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* 2-column grid */}
        <div className="grid grid-cols-2 gap-3">
          {filtered.map(v => <VulnCard key={v.id} v={v} />)}
        </div>

        {filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 gap-2">
            <p style={{ color: '#555555', fontSize: 11, fontFamily: 'monospace' }}>// No vulnerabilities match this filter</p>
            <button onClick={() => setFilter('ALL')} style={{ marginTop: 8, fontSize: 10, color: '#00ff41', background: 'none', border: '1px solid #00ff41', padding: '4px 14px', cursor: 'pointer', fontFamily: 'monospace' }}>
              SHOW ALL
            </button>
          </div>
        )}

        {/* Knowledge base stats */}
        {(() => {
          const total = vulnData.length;
          const severityCounts = {
            critical: vulnData.filter(v => v.severity === 'CRITICAL').length,
            high:     vulnData.filter(v => v.severity === 'HIGH').length,
            medium:   vulnData.filter(v => v.severity === 'MEDIUM').length,
          };
          return (
            <div className="font-mono text-xs border border-[#222] p-4 mt-2">
              <div className="text-[#00ff41] mb-3">{'> KNOWLEDGE_BASE_STATS'}</div>
              <div className="text-[#555] mb-2">{'──────────────────────────────'}</div>
              {[
                { label: 'CRITICAL', count: severityCounts.critical, color: '#ff4444' },
                { label: 'HIGH',     count: severityCounts.high,     color: '#ffaa00' },
                { label: 'MEDIUM',   count: severityCounts.medium,   color: '#00ff41' },
              ].map(({ label, count, color }) => {
                const pct    = Math.round(count / total * 100);
                const filled = Math.round(pct / 10);
                const bar    = '█'.repeat(filled) + '░'.repeat(10 - filled);
                return (
                  <div key={label} className="flex gap-4 mb-1 items-center">
                    <span className="w-16" style={{ color }}>[{label}]</span>
                    <span style={{ color }}>{bar}</span>
                    <span className="text-[#666]">{count} patterns · {pct}%</span>
                  </div>
                );
              })}
              <div className="text-[#555] mt-2 mb-3">{'──────────────────────────────'}</div>
              <div className="text-[#444]">
                {'  TOTAL'}
                <span className="text-[#888] ml-4">{total} vulnerability patterns documented</span>
              </div>
              <div className="text-[#333] mt-3">{'// Select a category above to filter'}</div>
              <div className="text-[#333]">{'// Click any card to expand attack details and fix recommendations'}</div>
            </div>
          );
        })()}

      </main>
    </div>
  );
}
