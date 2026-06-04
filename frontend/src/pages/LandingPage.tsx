import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';

const GREEN = '#00ff41';
const MATRIX_CHARS = 'ｦｧｨｩｪｫｬｭｮｯｰｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜﾝ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';

const SUBTITLE_LINES = [
  '// Finds security bugs in your Solidity contracts before attackers do',
  '// Detects common vulnerabilities — reentrancy attacks, permission flaws, and more',
  '// AI-powered analysis — explains how attacks work and how to fix them',
];

// ── Matrix rain + VULTRON title particles ────────────────────────────────────
function MatrixRain() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const RAIN_CHARS = (MATRIX_CHARS + 'ㄅㄆㄇㄈㄉㄊㄋㄌㄍㄎㄏㄐㄑㄒㄓㄔㄕㄖㄗㄘㄙㄧㄨㄩㄚㄛㄜㄝㄞㄟㄠㄡㄢㄣㄤㄥㄦ@#$%^&*<>+-/\\|{}[]').split('');
    const rc = () => RAIN_CHARS[Math.floor(Math.random() * RAIN_CHARS.length)];

    const COL_W   = 20;
    const BASE_FS = 16;
    interface RainCol { x: number; y: number; speed: number; char: string; }
    let rain: RainCol[] = [];

    function buildRain(W: number, H: number): RainCol[] {
      return Array.from({ length: Math.floor(W / COL_W) }, (_, i) => ({
        x: i * COL_W, y: Math.random() * H,
        speed: 2 + Math.random() * 3, char: rc(),
      }));
    }

    const P_SPACING   = 11;
    const FONT_SIZE   = 120;
    const TITLE_COLOR = '#1f1';
    const PHASE_DURS  = [100, 80, 300, 130];

    interface Particle {
      x: number; y: number;
      tx: number; ty: number;
      speed: number; char: string; ro: number;
    }

    let particles: Particle[] = [];
    let phase   = 0;
    let pTimer  = 0;
    let revealY = 0;
    let raf: number;

    function buildParticles(W: number, H: number) {
      const off = document.createElement('canvas');
      off.width = W; off.height = H;
      const oc = off.getContext('2d')!;
      oc.fillStyle = 'white';
      oc.font = `bold ${FONT_SIZE}px Courier New, monospace`;
      oc.textAlign = 'center';
      oc.textBaseline = 'middle';
      oc.fillText('VULTRON', W / 2, H * 0.35);
      const px = oc.getImageData(0, 0, W, H).data;
      const coords: Array<{ x: number; y: number }> = [];
      for (let y = 0; y < H; y += P_SPACING)
        for (let x = 0; x < W; x += P_SPACING)
          if (px[(y * W + x) * 4 + 3] > 128) coords.push({ x, y });
      particles = coords.map(c => ({
        x: c.x, y: Math.random() * H - H,
        tx: c.x, ty: c.y,
        speed: Math.random() * 4 + 4,
        char: rc(), ro: Math.random() * 60,
      }));
    }

    // Particles built ONCE from initial size — never rebuilt on resize
    const initW = window.innerWidth;
    const initH = window.innerHeight;
    canvas.width  = initW;
    canvas.height = initH;
    rain = buildRain(initW, initH);
    buildParticles(initW, initH);
    phase = 0; pTimer = 0; revealY = initH;

    function onResize() {
      canvas.width  = window.innerWidth;
      canvas.height = window.innerHeight;
      rain = buildRain(canvas.width, canvas.height);
      // particles intentionally NOT rebuilt
    }
    window.addEventListener('resize', onResize);

    const draw = () => {
      const W = canvas.width, H = canvas.height;

      ctx.fillStyle = 'rgba(0,0,0,0.15)';
      ctx.fillRect(0, 0, W, H);

      ctx.font      = `${BASE_FS}px monospace`;
      ctx.fillStyle = '#070';
      for (const c of rain) {
        ctx.fillText(c.char, c.x, c.y);
        c.char = rc(); c.y += c.speed;
        if (c.y > H) c.y = 0;
      }

      if (phase === 1) revealY -= initH / PHASE_DURS[1];

      for (const p of particles) {
        if (Math.random() < 0.05) p.char = rc();

        if (phase === 0) {
          p.y += p.speed;
          if (p.y > initH) p.y = Math.random() * -100;
        } else if (phase === 1) {
          if (p.ty >= revealY - p.ro) {
            if (p.y < p.ty) {
              p.y += p.speed * 5;
              if (p.y >= p.ty) p.y = p.ty;
            } else if (p.y > p.ty + 10) {
              p.y = Math.random() * -100;
            } else {
              p.y = p.ty;
            }
          } else {
            p.y += p.speed;
            if (p.y > initH) p.y = Math.random() * -50;
          }
        } else if (phase === 2) {
          // hold — stay formed with gentle flicker
          p.x = p.tx + (Math.random() - 0.5);
          p.y = p.ty + (Math.random() - 0.5);
        } else {
          // phase 3 — scatter back into rain
          p.y += p.speed * 1.5;
          p.x += (Math.random() - 0.5) * 2;
          if (p.y > initH) {
            p.y = Math.random() * -100;
            p.x = p.tx;
          }
        }

        ctx.shadowBlur  = (phase >= 1) ? 6 : 0;
        ctx.shadowColor = TITLE_COLOR;
        ctx.fillStyle   = TITLE_COLOR;
        ctx.font        = `bold ${P_SPACING + 2}px monospace`;
        ctx.fillText(p.char, p.x, p.y);
        ctx.shadowBlur  = 0;
      }

      // Cycle phase 0 → 1 → 2 → 3 → 0 → ...
      pTimer++;
      if (pTimer >= PHASE_DURS[phase]) {
        pTimer = 0;
        phase  = (phase + 1) % 4;
        if (phase === 1) revealY = initH;
      }

      raf = requestAnimationFrame(draw);
    };

    raf = requestAnimationFrame(draw);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return (
    <canvas ref={canvasRef} style={{
      position: 'fixed', top: 0, left: 0,
      width: '100%', height: '100%',
      zIndex: 0, pointerEvents: 'none', display: 'block',
    }} />
  );
}

// ── Typing subtitle ───────────────────────────────────────────────────────────
function TypingSubtitle() {
  const [lines, setLines]             = useState<string[]>([]);
  const [currentLine, setCurrentLine] = useState(0);
  const [currentChar, setCurrentChar] = useState(0);
  const [showCursor, setShowCursor]   = useState(true);

  useEffect(() => {
    const id = setInterval(() => setShowCursor(v => !v), 530);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    if (currentLine >= SUBTITLE_LINES.length) return;
    const target = SUBTITLE_LINES[currentLine];
    if (currentChar < target.length) {
      const id = setTimeout(() => setCurrentChar(c => c + 1), 28);
      return () => clearTimeout(id);
    }
    const id = setTimeout(() => {
      setLines(prev => [...prev, target]);
      setCurrentLine(l => l + 1);
      setCurrentChar(0);
    }, 500);
    return () => clearTimeout(id);
  }, [currentLine, currentChar]);

  const activeText = currentLine < SUBTITLE_LINES.length
    ? SUBTITLE_LINES[currentLine].slice(0, currentChar)
    : null;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginBottom: 24 }}>
      {lines.map((line, i) => (
        <p key={i} style={{ fontSize: 13, color: '#888888', margin: 0, fontFamily: "'Courier New', monospace" }}>
          <span style={{ color: '#444444' }}>// </span>{line.slice(3)}
        </p>
      ))}
      {activeText !== null && (
        <p style={{ fontSize: 13, color: '#888888', margin: 0, fontFamily: "'Courier New', monospace" }}>
          {activeText}
          <span style={{ display: 'inline-block', width: 8, color: GREEN, opacity: showCursor ? 1 : 0 }}>_</span>
        </p>
      )}
    </div>
  );
}

// ── Main page — locked fullscreen, no scroll ──────────────────────────────────
export default function LandingPage() {
  const navigate = useNavigate();
  const [visible,   setVisible]   = useState(false);
  const [showArrow, setShowArrow] = useState(true);

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 200);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    const id = setInterval(() => setShowArrow(v => !v), 2000);
    return () => clearInterval(id);
  }, []);

  const btnGreen: React.CSSProperties = {
    background: 'rgba(0,255,65,0.1)',
    border: `2px solid ${GREEN}`,
    color: GREEN,
    cursor: 'pointer',
    fontSize: 14,
    fontFamily: "'Courier New', monospace",
    letterSpacing: '0.12em',
    padding: '12px 28px',
    fontWeight: 700,
  };

  const btnGray: React.CSSProperties = {
    background: 'none',
    border: '1px solid #333333',
    color: '#888888',
    cursor: 'pointer',
    fontSize: 13,
    fontFamily: "'Courier New', monospace",
    letterSpacing: '0.12em',
    padding: '12px 24px',
    fontWeight: 700,
  };

  return (
    // Outer wrapper: locked fullscreen, no scroll whatsoever
    <div style={{
      position: 'fixed',
      inset: 0,
      background: '#000000',
      color: '#ffffff',
      fontFamily: "'Courier New', monospace",
      overflow: 'hidden',
    }}>
      <MatrixRain />

      {/* Navbar */}
      <nav style={{
        position: 'absolute',
        top: 0, left: 0, right: 0,
        zIndex: 50,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 32px',
        borderBottom: '1px solid #222222',
        background: 'rgba(0,0,0,0.85)',
      }}>
        <span style={{ fontSize: 16, fontWeight: 700, color: '#ffffff', letterSpacing: '0.1em' }}>
          VULTRON_
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
          {[
            { label: 'DASHBOARD', path: '/dashboard' },
            { label: 'ANALYZER',  path: '/analyzer'  },
          ].map(({ label, path }) => (
            <button
              key={label}
              onClick={() => navigate(path)}
              style={{ background: 'none', border: 'none', color: '#888888', cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', letterSpacing: '0.08em' }}
              onMouseEnter={e => (e.currentTarget.style.color = GREEN)}
              onMouseLeave={e => (e.currentTarget.style.color = '#888888')}
            >
              {label}
            </button>
          ))}
          <button
            onClick={() => navigate('/analyzer')}
            style={{ background: 'none', border: `1px solid ${GREEN}`, color: GREEN, cursor: 'pointer', fontSize: 12, fontFamily: 'inherit', letterSpacing: '0.1em', padding: '6px 14px' }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,255,65,0.08)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; }}
          >
            [ANALYZE]
          </button>
        </div>
      </nav>

      {/* Hero content — fixed below VULTRON canvas area */}
      {/* Canvas VULTRON center: 35vh, font 120px → bottom ≈ 35vh + 60px          */}
      {/* This box sits at the bottom 40% of the screen, completely separate layer  */}
      <div style={{
        position: 'absolute',
        bottom: '12vh',
        left: 0, right: 0,
        zIndex: 10,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        opacity: visible ? 1 : 0,
        transition: 'opacity 0.6s ease',
        pointerEvents: 'none',
      }}>
        {/* Text title */}
        <div style={{ marginBottom: 16, pointerEvents: 'none' }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#ffffff', lineHeight: 1.2, marginBottom: 6 }}>
            SOLIDITY CONTRACT
          </div>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#ffffff', letterSpacing: '0.18em' }}>
            SECURITY ANALYSIS PLATFORM
          </div>
        </div>

        <TypingSubtitle />

        {/* Buttons — re-enable pointer events just for these */}
        <div style={{ display: 'flex', gap: 12, pointerEvents: 'auto' }}>
          <button
            onClick={() => navigate('/analyzer')}
            style={btnGreen}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,255,65,0.18)'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'rgba(0,255,65,0.1)'; }}
          >
            [[ LAUNCH ANALYZER ]]&nbsp;
            <span style={{ opacity: showArrow ? 1 : 0, transition: 'opacity 0.4s ease' }}>»</span>
          </button>
          <button
            onClick={() => navigate('/analyzer')}
            style={btnGray}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(0,255,65,0.05)'; e.currentTarget.style.borderColor = '#555555'; e.currentTarget.style.color = '#aaaaaa'; }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.borderColor = '#333333'; e.currentTarget.style.color = '#888888'; }}
          >
            [[ VIEW DEMO ]]
          </button>
        </div>
      </div>
    </div>
  );
}
