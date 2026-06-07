import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import { getAuthHeaders, logout } from '../services/api';

const BASE = (import.meta.env.VITE_API_URL ?? 'http://localhost:8001') + '/api/auth';

interface AccountInfo {
  user_id: number;
  email: string;
  created_at: string | null;
}

const mono: React.CSSProperties = { fontFamily: "'Courier New', monospace" };

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ border: '1px solid #1e1e1e', background: '#0a0a0a', padding: 24, marginBottom: 16 }}>
      <p style={{ ...mono, color: '#555555', fontSize: 9, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 16 }}>
        // {title}
      </p>
      {children}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ marginBottom: 14 }}>
      <p style={{ ...mono, color: '#444444', fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4 }}>{label}</p>
      <p style={{ ...mono, color: '#aaaaaa', fontSize: 12 }}>{value}</p>
    </div>
  );
}

export default function AccountPage() {
  const [info, setInfo]               = useState<AccountInfo | null>(null);
  const [loadErr, setLoadErr]         = useState('');

  const [curPass, setCurPass]         = useState('');
  const [newPass, setNewPass]         = useState('');
  const [confirmPass, setConfirmPass] = useState('');
  const [pwMsg, setPwMsg]             = useState<{ ok: boolean; text: string } | null>(null);
  const [pwLoading, setPwLoading]     = useState(false);

  useEffect(() => {
    fetch(`${BASE}/me`, { headers: getAuthHeaders() })
      .then(r => r.json())
      .then(json => {
        if (json.status === 'success') setInfo(json.data);
        else setLoadErr(json.message ?? 'Failed to load account');
      })
      .catch(() => setLoadErr('Cannot connect to server'));
  }, []);

  const handleChangePassword = async () => {
    if (!curPass || !newPass || !confirmPass) {
      setPwMsg({ ok: false, text: 'All fields are required.' });
      return;
    }
    if (newPass !== confirmPass) {
      setPwMsg({ ok: false, text: 'New passwords do not match.' });
      return;
    }
    if (newPass.length < 8) {
      setPwMsg({ ok: false, text: 'New password must be at least 8 characters.' });
      return;
    }
    setPwLoading(true);
    setPwMsg(null);
    try {
      const res = await fetch(`${BASE}/password`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...getAuthHeaders() },
        body: JSON.stringify({ current_password: curPass, new_password: newPass }),
      });
      const json = await res.json();
      if (json.status === 'success') {
        setPwMsg({ ok: true, text: 'Password updated successfully.' });
        setCurPass(''); setNewPass(''); setConfirmPass('');
      } else {
        const msgs: Record<string, string> = {
          WRONG_PASSWORD: 'Current password is incorrect.',
          WEAK_PASSWORD:  'New password must be at least 8 characters.',
        };
        setPwMsg({ ok: false, text: msgs[json.code] ?? json.message ?? 'Update failed.' });
      }
    } catch {
      setPwMsg({ ok: false, text: 'Cannot connect to server.' });
    } finally {
      setPwLoading(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: '#0d0d0d',
    border: '1px solid #2a2a2a',
    color: '#cccccc',
    ...mono,
    fontSize: 12,
    padding: '9px 12px',
    outline: 'none',
    boxSizing: 'border-box',
  };

  const formatDate = (iso: string | null) => {
    if (!iso) return '—';
    try {
      return new Date(iso).toLocaleString('zh-TW', {
        year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      });
    } catch { return iso; }
  };

  return (
    <div className="flex h-screen bg-[#000000] overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-y-auto p-8">
        <div style={{ maxWidth: 560, margin: '0 auto' }}>

          {/* Header */}
          <div style={{ marginBottom: 28 }}>
            <p style={{ ...mono, color: '#00ff41', fontSize: 10, letterSpacing: '0.14em', marginBottom: 6 }}>
              &gt; ACCOUNT_SETTINGS
            </p>
            <h1 style={{ ...mono, color: '#e2e8f0', fontSize: 20, fontWeight: 700, letterSpacing: '0.06em' }}>
              Account Settings
            </h1>
          </div>

          {/* Account Info */}
          <Section title="Account Info">
            {loadErr ? (
              <p style={{ ...mono, color: '#ef4444', fontSize: 11 }}>✗ {loadErr}</p>
            ) : !info ? (
              <p style={{ ...mono, color: '#555555', fontSize: 11 }}>// Loading...</p>
            ) : (
              <>
                <Field label="Email"      value={info.email} />
                <Field label="User ID"    value={`#${info.user_id}`} />
                <Field label="Registered" value={formatDate(info.created_at)} />
              </>
            )}
          </Section>

          {/* Change Password */}
          <Section title="Change Password">
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {(['Current Password', 'New Password', 'Confirm New Password'] as const).map((label, i) => {
                const vals   = [curPass, newPass, confirmPass];
                const setters = [setCurPass, setNewPass, setConfirmPass];
                return (
                  <div key={label}>
                    <label style={{ display: 'block', ...mono, color: '#555555', fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>
                      {label}
                    </label>
                    <input
                      type="password"
                      value={vals[i]}
                      onChange={e => setters[i](e.target.value)}
                      onKeyDown={e => e.key === 'Enter' && handleChangePassword()}
                      placeholder="••••••••"
                      style={inputStyle}
                      onFocus={e => (e.target.style.borderColor = '#00ff41')}
                      onBlur={e => (e.target.style.borderColor = '#2a2a2a')}
                    />
                  </div>
                );
              })}

              {pwMsg && (
                <p style={{ ...mono, fontSize: 11, color: pwMsg.ok ? '#00ff41' : '#ef4444', margin: 0 }}>
                  {pwMsg.ok ? '✓' : '✗'} {pwMsg.text}
                </p>
              )}

              <button
                onClick={handleChangePassword}
                disabled={pwLoading}
                style={{
                  ...mono,
                  background: pwLoading ? 'rgba(0,255,65,0.03)' : 'rgba(0,255,65,0.07)',
                  border: '1px solid #00ff41',
                  color: '#00ff41',
                  fontSize: 11,
                  fontWeight: 700,
                  letterSpacing: '0.1em',
                  padding: '10px',
                  cursor: pwLoading ? 'not-allowed' : 'pointer',
                  textTransform: 'uppercase',
                  marginTop: 4,
                  width: '100%',
                }}
              >
                {pwLoading ? '// UPDATING...' : '[[ UPDATE PASSWORD ]]'}
              </button>
            </div>
          </Section>

          {/* Danger zone */}
          <Section title="Session">
            <p style={{ ...mono, color: '#555555', fontSize: 10, marginBottom: 14, lineHeight: 1.6 }}>
              // Logging out will clear your local session token. You will need to log in again to access the platform.
            </p>
            <button
              onClick={logout}
              style={{
                ...mono,
                background: 'rgba(239,68,68,0.06)',
                border: '1px solid #7f1d1d',
                color: '#ef4444',
                fontSize: 11,
                fontWeight: 700,
                letterSpacing: '0.1em',
                padding: '10px 20px',
                cursor: 'pointer',
                textTransform: 'uppercase',
              }}
            >
              [[ LOGOUT ]]
            </button>
          </Section>

        </div>
      </main>
    </div>
  );
}
