import React, { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, ScanSearch, FileText, ShieldAlert, Settings } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import LanguageToggle from './LanguageToggle';
import { logout } from '../services/api';

const BASE = import.meta.env.VITE_API_URL ?? 'http://localhost:8001';

type GroqStatus = 'checking' | 'ok' | 'error';

export default function Sidebar() {
  const loc = useLocation();
  const { t } = useTranslation();
  const email = localStorage.getItem('vultron_email');
  const [groqStatus, setGroqStatus] = useState<GroqStatus>('checking');

  useEffect(() => {
    let cancelled = false;
    const check = async () => {
      try {
        const res = await fetch(`${BASE}/api/health`, { signal: AbortSignal.timeout(6000) });
        const json = await res.json();
        if (!cancelled) setGroqStatus(json.groq === 'ok' ? 'ok' : 'error');
      } catch {
        if (!cancelled) setGroqStatus('error');
      }
    };
    check();
    const timer = setInterval(check, 60_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, []);

  const nav = [
    { icon: LayoutDashboard, labelKey: 'sidebar.dashboard',        to: '/dashboard'      },
    { icon: ScanSearch,      labelKey: 'sidebar.analyzer',         to: '/analyzer'       },
    { icon: FileText,        labelKey: 'sidebar.reports',          to: '/report'         },
    { icon: ShieldAlert,     labelKey: 'sidebar.vulnerabilities',  to: '/vulnerabilities'},
  ];

  return (
    <aside style={{ fontFamily: "'Courier New', monospace" }}
      className="w-48 flex-shrink-0 h-full bg-[#0d0d0d] border-r border-[#222222] flex flex-col"
    >
      {/* Logo */}
      <Link to="/" className="flex items-center gap-2 px-4 py-3.5 border-b border-[#222222] group">
        <span className="font-bold text-sm tracking-widest" style={{ color: '#00ff41', fontFamily: "'Courier New', monospace" }}>
          VULTRON_
        </span>
      </Link>

      {/* Breadcrumb */}
      {(() => {
        const labels: Record<string, string> = {
          '/dashboard':      'DASHBOARD',
          '/analyzer':       'ANALYZER',
          '/report':         'REPORT',
          '/vulnerabilities':'VULN_DB',
          '/account':        'ACCOUNT',
        };
        const label = labels[loc.pathname];
        return label ? (
          <div className="px-4 py-1.5 border-b border-[#1a1a1a]">
            <p style={{ fontSize: 9, color: '#444444', fontFamily: "'Courier New', monospace", letterSpacing: '0.06em' }}>
              VULTRON_ / <span style={{ color: '#666666' }}>{label}</span>
            </p>
          </div>
        ) : null;
      })()}

      {/* Nav items */}
      <nav className="flex-1 p-2 flex flex-col gap-0.5 mt-1">
        <p className="px-3 pt-1 pb-2 text-[9px] font-bold tracking-widest text-[#555555] uppercase" style={{ fontFamily: "'Courier New', monospace" }}>
          Navigation
        </p>
        {nav.map(({ icon: Icon, labelKey, to }) => {
          const active = loc.pathname === to || (to !== '/dashboard' && loc.pathname.startsWith(to));
          return (
            <Link
              key={to}
              to={to}
              className={`flex items-center gap-2.5 px-3 py-2 text-xs font-medium transition-all duration-100 border-l-2 ${
                active
                  ? 'border-l-[#00ff41] bg-[rgba(0,255,65,0.06)] text-[#00ff41]'
                  : 'border-l-transparent text-[#777777] hover:text-[#aaaaaa] hover:bg-[rgba(0,255,65,0.02)]'
              }`}
              style={{ fontFamily: "'Courier New', monospace" }}
            >
              <Icon size={13} />
              <span className="uppercase tracking-wide text-[10px]">{t(labelKey)}</span>
            </Link>
          );
        })}
      </nav>

      {/* Footer */}
      <div className="p-3 border-t border-[#222222] flex flex-col gap-2">
        <LanguageToggle />
        <Link
          to="/account"
          style={{ fontFamily: "'Courier New', monospace" }}
          className={`flex items-center gap-2 px-3 py-2 text-[10px] uppercase tracking-wide border transition-colors ${
            loc.pathname === '/account'
              ? 'border-[#333333] text-[#00ff41] bg-[rgba(0,255,65,0.05)]'
              : 'border-[#1e1e1e] text-[#555555] hover:text-[#888888] hover:border-[#2a2a2a]'
          }`}
        >
          <Settings size={11} />
          {t('sidebar.account')}
        </Link>
        {(() => {
          const cfg = {
            ok:       { dot: '#00ff41', label: 'Engine Active',    sub: 'Groq Llama-3.1',   border: '#222222', bg: 'rgba(0,255,65,0.03)',  pulse: true  },
            error:    { dot: '#ef4444', label: 'Engine Offline',   sub: 'Groq unreachable', border: '#3f1111', bg: 'rgba(239,68,68,0.04)', pulse: false },
            checking: { dot: '#555555', label: 'Checking...',      sub: 'Groq Llama-3.1',   border: '#222222', bg: 'transparent',          pulse: true  },
          }[groqStatus];
          return (
            <div style={{ padding: '8px 12px', border: `1px solid ${cfg.border}`, background: cfg.bg }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  width: 6, height: 6, borderRadius: '50%', background: cfg.dot, flexShrink: 0,
                  animation: cfg.pulse ? 'pulse 2s cubic-bezier(0.4,0,0.6,1) infinite' : 'none',
                }} />
                <p style={{ fontFamily: "'Courier New', monospace", fontSize: 10, color: cfg.dot, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                  {cfg.label}
                </p>
              </div>
              <p style={{ fontFamily: "'Courier New', monospace", fontSize: 9, color: '#555555', marginTop: 3 }}>
                {cfg.sub}
              </p>
            </div>
          );
        })()}

      </div>
    </aside>
  );
}
