import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Zap, GitBranch, Bot, BarChart3, ChevronRight, Lock } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import LanguageToggle from '../components/LanguageToggle';

export default function LandingPage() {
  const navigate = useNavigate();
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 300);
    return () => clearTimeout(timer);
  }, []);

  const featureKeys = ['vuln', 'attack', 'graph', 'defense', 'score'] as const;
  const featureIcons = [Shield, Zap, GitBranch, Bot, BarChart3];
  const featureColors = [
    { text: 'text-violet-400', bg: 'bg-violet-500/8', border: 'border-violet-500/20' },
    { text: 'text-orange-400', bg: 'bg-orange-500/8', border: 'border-orange-500/20' },
    { text: 'text-blue-400', bg: 'bg-blue-500/8', border: 'border-blue-500/20' },
    { text: 'text-green-400', bg: 'bg-green-500/8', border: 'border-green-500/20' },
    { text: 'text-yellow-400', bg: 'bg-yellow-500/8', border: 'border-yellow-500/20' },
  ];

  const stats = [
    { v: '50K+', k: 'landing.stats.contracts' },
    { v: '$4.2B', k: 'landing.stats.protected' },
    { v: '99.4%', k: 'landing.stats.detection' },
    { v: '5', k: 'landing.stats.modules' },
  ];

  return (
    <div className="min-h-screen bg-[#080810] text-white overflow-x-hidden" style={{ fontFamily: 'Sora, Inter, sans-serif' }}>
      {/* Animated grid */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute inset-0 opacity-[0.025]" style={{
          backgroundImage: 'linear-gradient(rgba(124,58,237,1) 1px, transparent 1px), linear-gradient(90deg, rgba(124,58,237,1) 1px, transparent 1px)',
          backgroundSize: '48px 48px',
        }} />
        <div className="absolute inset-0 bg-gradient-to-b from-transparent via-[#080810]/20 to-[#080810]" />
        <div className="absolute top-1/3 left-1/3 w-[500px] h-[500px] rounded-full bg-violet-700/5 blur-3xl" />
        <div className="absolute bottom-1/3 right-1/3 w-[400px] h-[400px] rounded-full bg-blue-700/4 blur-3xl" />
      </div>

      {/* Navbar */}
      <nav className="relative z-10 flex items-center justify-between px-8 py-4 border-b border-[#1e1e30]/60">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-violet-600 flex items-center justify-center shadow-[0_0_18px_rgba(124,58,237,0.6)]">
            <Shield size={15} className="text-white" />
          </div>
          <span className="font-bold text-lg tracking-tight">Vultron</span>
        </div>
        <div className="flex items-center gap-4">
          <button onClick={() => navigate('/dashboard')} className="text-sm text-slate-400 hover:text-white transition-colors">{t('landing.navDashboard')}</button>
          <button onClick={() => navigate('/attack-generator')} className="text-sm text-slate-400 hover:text-white transition-colors">{t('landing.navAttackSim')}</button>
          <button onClick={() => navigate('/analyzer')} className="btn btn-primary text-sm">{t('landing.navAnalyzer')}</button>
          <LanguageToggle />
        </div>
      </nav>

      {/* Hero */}
      <section className="relative z-10 flex flex-col items-center text-center px-6 pt-20 pb-16">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-violet-500/10 border border-violet-500/20 mb-8">
          <Lock size={11} className="text-violet-400" />
          <span className="text-xs text-violet-300 font-medium">{t('landing.badge')}</span>
        </div>

        <h1
          className="text-5xl md:text-6xl font-bold mb-5 leading-tight max-w-4xl"
          style={{ opacity: visible ? 1 : 0, transform: visible ? 'none' : 'translateY(16px)', transition: 'all 0.7s ease' }}
        >
          <span className="text-white">{t('landing.title1')}</span><br />
          <span className="text-gradient">{t('landing.title2')}</span><br />
          <span className="text-white">{t('landing.title3')}</span>
        </h1>

        <p
          className="text-lg text-slate-400 mb-10 max-w-2xl"
          style={{ opacity: visible ? 1 : 0, transform: visible ? 'none' : 'translateY(12px)', transition: 'all 0.7s ease 0.2s' }}
        >
          {t('landing.subtitle')}{' '}
          <span className="text-violet-300 font-semibold">{t('landing.subtitleHighlight')}</span>
        </p>

        <div className="flex gap-4 mb-16" style={{ opacity: visible ? 1 : 0, transition: 'opacity 0.7s ease 0.4s' }}>
          <button
            onClick={() => navigate('/analyzer')}
            className="flex items-center gap-2 px-7 py-3.5 bg-violet-600 hover:bg-[#6d28d9] text-white font-bold rounded-xl transition-all duration-200 hover:shadow-[0_0_28px_rgba(124,58,237,0.5)] text-base"
          >
            {t('landing.launchAnalyzer')} <ChevronRight size={18} />
          </button>
          <button
            onClick={() => navigate('/attack-generator')}
            className="flex items-center gap-2 px-7 py-3.5 bg-[#13131f] hover:bg-[#1a1a2e] text-white font-semibold rounded-xl border border-[#1e1e30] transition-all duration-200 text-base"
          >
            {t('landing.viewDemoAttack')} <Zap size={16} className="text-orange-400" />
          </button>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-8 max-w-2xl w-full">
          {stats.map(({ v, k }) => (
            <div key={k} className="text-center">
              <div className="text-2xl font-bold text-white">{v}</div>
              <div className="text-xs text-slate-500 mt-0.5">{t(k)}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="relative z-10 px-6 py-16 max-w-6xl mx-auto">
        <div className="text-center mb-12">
          <h2 className="text-3xl font-bold text-white mb-3">{t('landing.featuresTitle')}</h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">{t('landing.featuresSubtitle')}</p>
        </div>
        <div className="grid md:grid-cols-3 gap-5">
          {featureKeys.map((key, i) => {
            const Icon = featureIcons[i];
            const { text, bg, border } = featureColors[i];
            return (
              <div key={key} className={`p-5 rounded-2xl border ${border} ${bg} hover:scale-[1.02] transition-transform duration-200 cursor-default`}>
                <div className={`w-9 h-9 rounded-xl ${bg} border ${border} flex items-center justify-center mb-3`}>
                  <Icon size={18} className={text} />
                </div>
                <h3 className="text-sm font-bold text-white mb-1.5">{t(`landing.features.${key}.title`)}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{t(`landing.features.${key}.desc`)}</p>
              </div>
            );
          })}
        </div>
      </section>

      {/* CTA */}
      <section className="relative z-10 px-6 py-16">
        <div className="max-w-2xl mx-auto text-center p-10 rounded-3xl bg-gradient-to-br from-violet-500/8 to-blue-500/5 border border-violet-500/20">
          <h2 className="text-2xl font-bold text-white mb-3">{t('landing.ctaTitle')}</h2>
          <p className="text-slate-400 text-sm mb-6">{t('landing.ctaDesc')}</p>
          <button onClick={() => navigate('/analyzer')} className="px-8 py-3.5 bg-violet-600 hover:bg-[#6d28d9] text-white font-bold rounded-xl transition-all duration-200 hover:shadow-[0_0_24px_rgba(124,58,237,0.5)]">
            {t('landing.ctaButton')}
          </button>
        </div>
      </section>

      <footer className="relative z-10 border-t border-[#1e1e30] px-6 py-6 text-center">
        <p className="text-xs text-slate-600">{t('landing.footerText')}</p>
      </footer>
    </div>
  );
}
