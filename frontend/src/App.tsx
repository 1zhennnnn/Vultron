import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import DashboardPage from './pages/DashboardPage';
import MainDashboard from './pages/MainDashboard';
import ReportPage from './pages/ReportPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';
import AuthPage from './pages/AuthPage';
import AccountPage from './pages/AccountPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('vultron_token');
  if (!token) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <Routes>
        <Route path="/"              element={<LandingPage />} />
        <Route path="/login"         element={<AuthPage />} />
        <Route path="/dashboard"     element={<ProtectedRoute><DashboardPage /></ProtectedRoute>} />
        <Route path="/analyzer"      element={<ProtectedRoute><MainDashboard /></ProtectedRoute>} />
        <Route path="/report"        element={<ProtectedRoute><ReportPage /></ProtectedRoute>} />
        <Route path="/vulnerabilities" element={<ProtectedRoute><VulnerabilitiesPage /></ProtectedRoute>} />
        <Route path="/account"       element={<ProtectedRoute><AccountPage /></ProtectedRoute>} />
        <Route path="*"              element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
