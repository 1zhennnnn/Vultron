import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';

const BASE = (import.meta.env.VITE_API_URL ?? 'http://localhost:8001') + '/api/auth';

type Tab = 'login' | 'register';

export default function AuthPage() {
  const navigate = useNavigate();
  const [tab, setTab]         = useState<Tab>('login');
  const [email, setEmail]     = useState('');
  const [password, setPass]   = useState('');
  const [error, setError]     = useState('');
  const [loading, setLoading] = useState(false);

  const submit = async () => {
    if (!email.trim() || !password.trim()) {
      setError('Email and password are required.');
      return;
    }
    setLoading(true);
    setError('');
    try {
      const res = await fetch(`${BASE}/${tab}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      const json = await res.json();

      if (json.status === 'error') {
        const msg: Record<string, string> = {
          EMAIL_EXISTS: 'Email already registered. Please log in.',
          INVALID_CREDENTIALS: 'Incorrect email or password.',
        };
        setError(msg[json.code] ?? json.message ?? 'Request failed.');
        return;
      }

      const { token, email: userEmail } = json.data;
      localStorage.setItem('vultron_token', token);
      localStorage.setItem('vultron_email', userEmail);
      navigate('/analyzer');
    } catch {
      setError('Cannot connect to server. Check your connection.');
    } finally {
      setLoading(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: '#0d0d0d',
    border: '1px solid #333333',
    color: '#e2e8f0',
    fontFamily: "'Courier New', monospace",
    fontSize: 13,
    padding: '10px 12px',
    outline: 'none',
    boxSizing: 'border-box',
  };

  return (
    <div style={{
      minHeight: '100vh',
      background: '#000000',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      fontFamily: "'Courier New', monospace",
    }}>
      <div style={{ width: '100%', maxWidth: 400, padding: '0 16px' }}>

        {/* Header */}
        <div style={{ marginBottom: 32, textAlign: 'center' }}>
          <p style={{ color: '#00ff41', fontSize: 11, letterSpacing: '0.15em', marginBottom: 8 }}>
            &gt; VULTRON_ ACCESS CONTROL
          </p>
          <p style={{ color: '#374151', fontSize: 10, letterSpacing: '0.08em' }}>
            // Smart Contract Security Platform
          </p>
        </div>

        {/* Card */}
        <div style={{ border: '1px solid #222222', background: '#0a0a0a', padding: 28 }}>

          {/* Tab bar */}
          <div style={{ display: 'flex', borderBottom: '1px solid #222222', marginBottom: 24 }}>
            {(['login', 'register'] as Tab[]).map(t => (
              <button
                key={t}
                onClick={() => { setTab(t); setError(''); }}
                style={{
                  flex: 1,
                  background: 'none',
                  border: 'none',
                  borderBottom: tab === t ? '2px solid #00ff41' : '2px solid transparent',
                  color: tab === t ? '#00ff41' : '#555555',
                  fontFamily: "'Courier New', monospace",
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: '0.12em',
                  padding: '8px 0',
                  cursor: 'pointer',
                  textTransform: 'uppercase',
                }}
              >
                [ {t === 'login' ? 'LOGIN' : 'REGISTER'} ]
              </button>
            ))}
          </div>

          {/* Fields */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div>
              <label style={{ display: 'block', color: '#555555', fontSize: 9, letterSpacing: '0.1em', marginBottom: 6, textTransform: 'uppercase' }}>
                Email
              </label>
              <input
                type="email"
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && submit()}
                placeholder="user@example.com"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = '#00ff41')}
                onBlur={e => (e.target.style.borderColor = '#333333')}
              />
            </div>

            <div>
              <label style={{ display: 'block', color: '#555555', fontSize: 9, letterSpacing: '0.1em', marginBottom: 6, textTransform: 'uppercase' }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => setPass(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && submit()}
                placeholder="••••••••"
                style={inputStyle}
                onFocus={e => (e.target.style.borderColor = '#00ff41')}
                onBlur={e => (e.target.style.borderColor = '#333333')}
              />
            </div>

            {/* Error */}
            {error && (
              <p style={{ color: '#ef4444', fontSize: 11, fontFamily: "'Courier New', monospace", margin: 0 }}>
                ✗ {error}
              </p>
            )}

            {/* Submit */}
            <button
              onClick={submit}
              disabled={loading}
              style={{
                width: '100%',
                background: loading ? 'rgba(0,255,65,0.04)' : 'rgba(0,255,65,0.08)',
                border: '1px solid #00ff41',
                color: '#00ff41',
                fontFamily: "'Courier New', monospace",
                fontSize: 12,
                fontWeight: 700,
                letterSpacing: '0.12em',
                padding: '12px',
                cursor: loading ? 'not-allowed' : 'pointer',
                textTransform: 'uppercase',
                marginTop: 4,
              }}
            >
              {loading ? '// AUTHENTICATING...' : tab === 'login' ? '[[ LOGIN ]]' : '[[ CREATE ACCOUNT ]]'}
            </button>
          </div>

          {/* Switch tab hint */}
          <p style={{ textAlign: 'center', marginTop: 18, color: '#374151', fontSize: 10 }}>
            {tab === 'login' ? "No account? " : "Already registered? "}
            <span
              onClick={() => { setTab(tab === 'login' ? 'register' : 'login'); setError(''); }}
              style={{ color: '#555555', cursor: 'pointer', textDecoration: 'underline' }}
            >
              {tab === 'login' ? 'Register' : 'Log in'}
            </span>
          </p>
        </div>

        {/* Footer */}
        <p style={{ textAlign: 'center', marginTop: 20, color: '#1f2937', fontSize: 9, letterSpacing: '0.08em' }}>
          // VULTRON v4 — Powered by Slither + Groq
        </p>
      </div>
    </div>
  );
}
