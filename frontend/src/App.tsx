import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import AgentDetail from './pages/AgentDetail';
import AdminConfig from './pages/AdminConfig';
import AdminUsers from './pages/AdminUsers';
import AIAnalysis from './pages/AIAnalysis';
import ThreatIntel from './pages/ThreatIntel';
import AttackCoverage from './pages/AttackCoverage';
import Login from './pages/Login';
import Playbooks from './pages/Playbooks';
import Databases from './pages/Databases';
import LoginLogs from './pages/LoginLogs';
import AuditLogs from './pages/AuditLogs';
import Automations from './pages/Automations';
import GlobalAlerts from './pages/GlobalAlerts';
import Agents from './pages/Agents';
import Deployment from './pages/Deployment';
import SoarHub from './pages/SoarHub';
import Assets from './pages/Assets';
import FileIntegrity from './pages/FileIntegrity';
import LogSearch from './pages/LogSearch';
import { authService } from './services/api';

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const location = useLocation();
  
  if (!authService.isAuthenticated()) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <Layout>{children}</Layout>;
};

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        
        <Route path="/" element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        
        <Route path="/agents" element={
          <ProtectedRoute>
            <Agents />
          </ProtectedRoute>
        } />

        <Route path="/agent/:agentName" element={
          <ProtectedRoute>
            <AgentDetail />
          </ProtectedRoute>
        } />
        
        <Route path="/all-alerts" element={
          <ProtectedRoute>
            <GlobalAlerts />
          </ProtectedRoute>
        } />

        <Route path="/threat-intel" element={
          <ProtectedRoute>
            <ThreatIntel />
          </ProtectedRoute>
        } />

        <Route path="/attack-coverage" element={
          <ProtectedRoute>
            <AttackCoverage />
          </ProtectedRoute>
        } />
        
        <Route path="/deployment" element={
          <ProtectedRoute>
            <Deployment />
          </ProtectedRoute>
        } />
        
        <Route path="/playbooks" element={
          <ProtectedRoute>
            <Playbooks />
          </ProtectedRoute>
        } />
        
        <Route path="/automations" element={
          <ProtectedRoute>
            <Automations />
          </ProtectedRoute>
        } />

        <Route path="/soar-hub" element={
          <ProtectedRoute>
            <SoarHub />
          </ProtectedRoute>
        } />
        
        <Route path="/admin/config" element={
          <ProtectedRoute>
            <AdminConfig />
          </ProtectedRoute>
        } />
        
        <Route path="/admin/users" element={
          <ProtectedRoute>
            <AdminUsers />
          </ProtectedRoute>
        } />
        
        <Route path="/admin/databases" element={
          <ProtectedRoute>
            <Databases />
          </ProtectedRoute>
        } />

        <Route path="/admin/login-logs" element={
          <ProtectedRoute>
            <LoginLogs />
          </ProtectedRoute>
        } />

        <Route path="/admin/audit" element={
          <ProtectedRoute>
            <AuditLogs />
          </ProtectedRoute>
        } />
        
        <Route path="/ai-analysis" element={
          <ProtectedRoute>
            <AIAnalysis />
          </ProtectedRoute>
        } />
        
        <Route path="/assets" element={
          <ProtectedRoute>
            <Assets />
          </ProtectedRoute>
        } />

        <Route path="/fim" element={
          <ProtectedRoute>
            <FileIntegrity />
          </ProtectedRoute>
        } />

        <Route path="/log-search" element={
          <ProtectedRoute>
            <LogSearch />
          </ProtectedRoute>
        } />
        
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;
