import React from 'react';
import { useTranslation } from 'react-i18next';
import { Globe } from 'lucide-react';

export default function LanguageToggle() {
  const { i18n } = useTranslation();
  const current = i18n.language;

  const toggle = (lang: string) => {
    i18n.changeLanguage(lang);
  };

  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded-lg bg-[#1e1e30] border border-[#2a2a40]">
      <Globe size={12} className="text-slate-500" />
      <button
        onClick={() => toggle('en')}
        className={`text-xs font-semibold px-1.5 py-0.5 rounded transition-all duration-150 ${
          current === 'en'
            ? 'bg-violet-600 text-white'
            : 'text-slate-400 hover:text-white'
        }`}
      >
        EN
      </button>
      <span className="text-slate-600 text-xs">|</span>
      <button
        onClick={() => toggle('zh')}
        className={`text-xs font-semibold px-1.5 py-0.5 rounded transition-all duration-150 ${
          current === 'zh'
            ? 'bg-violet-600 text-white'
            : 'text-slate-400 hover:text-white'
        }`}
      >
        中文
      </button>
    </div>
  );
}
