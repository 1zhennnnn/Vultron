import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { LayoutDashboard, ScanSearch, Zap, FileText, Shield } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import LanguageToggle from './LanguageToggle';

export default function Sidebar() {
  const loc = useLocation();
  const { t } = useTranslation();

  const nav = [
    { icon: LayoutDashboard, labelKey: 'sidebar.dashboard', to: '/dashboard' },
    { icon: ScanSearch, labelKey: 'sidebar.analyzer', to: '/analyzer' },
    { icon: Zap, labelKey: 'sidebar.attackGenerator', to: '/attack-generator' },
    { icon: FileText, labelKey: 'sidebar.reports', to: '/report' },
  ];

  return (
    <aside className="w-56 flex-shrink-0 h-full bg-[#080810] border-r border-[#1e1e30] flex flex-col">
      <Link to="/" className="flex items-center gap-2.5 px-5 py-4 border-b border-[#1e1e30] group">
        <div className="w-7 h-7 rounded-lg bg-violet-600 flex items-center justify-center shadow-[0_0_14px_rgba(124,58,237,0.5)] group-hover:shadow-[0_0_20px_rgba(124,58,237,0.8)] transition-all">
          <Shield size={14} className="text-white" />
        </div>
        <span className="font-bold text-white text-base tracking-tight">Vultron</span>
      </Link>

      <nav className="flex-1 p-3 flex flex-col gap-1">
        {nav.map(({ icon: Icon, labelKey, to }) => {
          const active = loc.pathname === to || (to !== '/dashboard' && loc.pathname.startsWith(to));
          return (
            <Link
              key={to}
              to={to}
              className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 ${
                active
                  ? 'bg-violet-500/15 text-violet-300 border border-violet-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a1a28]'
              }`}
            >
              <Icon size={15} className={active ? 'text-violet-400' : ''} />
              {t(labelKey)}
            </Link>
          );
        })}
      </nav>

      <div className="p-4 border-t border-[#1e1e30] flex flex-col gap-2">
        <LanguageToggle />
        <div className="px-3 py-2 rounded-lg bg-violet-500/5 border border-violet-500/15 text-center">
          <p className="text-xs text-violet-400 font-bold">{t('sidebar.copilotActive')}</p>
          <p className="text-[10px] text-slate-600 mt-0.5">{t('sidebar.engineLabel')}</p>
        </div>
      </div>
    </aside>
  );
}
