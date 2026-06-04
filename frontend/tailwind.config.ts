import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       '#0f1117',
        surface:  '#161b27',
        card:     '#161b27',
        border:   '#1f2937',
        primary:  { DEFAULT: '#f97316', dim: 'rgba(249,115,22,0.12)', text: '#fb923c' },
        secondary: { DEFAULT: '#3b82f6', dim: 'rgba(59,130,246,0.12)' },
        danger:   { DEFAULT: '#ef4444', dim: 'rgba(239,68,68,0.12)' },
        warning:  { DEFAULT: '#f59e0b', dim: 'rgba(245,158,11,0.12)' },
        success:  { DEFAULT: '#10b981', dim: 'rgba(16,185,129,0.12)' },
        fore:     '#e2e8f0',
        muted:    '#94a3b8',
        subtle:   '#64748b',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', '"Fira Code"', 'monospace'],
        sans: ['Inter', '"IBM Plex Sans"', 'system-ui', 'sans-serif'],
      },
      borderRadius: {
        DEFAULT: '2px',
        sm:      '2px',
        md:      '2px',
        lg:      '2px',
        xl:      '2px',
        '2xl':   '2px',
        '3xl':   '2px',
        full:    '9999px',
      },
      animation: {
        'fade-in':  'fadeIn 0.3s ease-out',
        'slide-up': 'slideUp 0.25s ease-out',
      },
      keyframes: {
        fadeIn:  { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: { '0%': { opacity: '0', transform: 'translateY(6px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
};

export default config;
