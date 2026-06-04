import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import LandingPage from './pages/LandingPage';
import DashboardPage from './pages/DashboardPage';
import MainDashboard from './pages/MainDashboard';
import ReportPage from './pages/ReportPage';
import VulnerabilitiesPage from './pages/VulnerabilitiesPage';

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<LandingPage />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="/analyzer" element={<MainDashboard />} />
        <Route path="/report" element={<ReportPage />} />
        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
