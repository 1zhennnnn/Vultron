import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, ScanSearch, FileText, ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import LanguageToggle from './LanguageToggle';

export default function Sidebar() {
  const loc = useLocation();
  const { t } = useTranslation();

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
        <div className="px-3 py-2 border border-[#222222] bg-[rgba(0,255,65,0.03)]">
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-[#00ff41] animate-pulse flex-shrink-0" />
            <p className="text-[10px] text-[#00ff41] font-bold uppercase tracking-wider" style={{ fontFamily: "'Courier New', monospace" }}>
              Engine Active
            </p>
          </div>
          <p className="text-[9px] text-[#555555] mt-0.5" style={{ fontFamily: "'Courier New', monospace" }}>
            Groq Llama-3.1
          </p>
        </div>
      </div>
    </aside>
  );
}
