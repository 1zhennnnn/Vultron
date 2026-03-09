import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#080810',
        surface: '#0f0f1a',
        card: '#13131f',
        border: '#1e1e30',
        accent: { DEFAULT: '#7c3aed', hover: '#6d28d9', light: '#a78bfa' },
        danger: '#ef4444',
        warning: '#f97316',
        success: '#22c55e',
        info: '#3b82f6',
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'monospace'],
        sans: ['Sora', 'Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-out',
        'slide-up': 'slideUp 0.4s ease-out',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
        typewriter: 'typewriter 0.05s steps(1) forwards',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(16px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 10px rgba(124,58,237,0.3)' },
          '50%': { boxShadow: '0 0 25px rgba(124,58,237,0.7)' },
        },
      },
    },
  },
  plugins: [],
};

export default config;
