import React, { useState, useEffect } from 'react';
import Sidebar from './Sidebar';
import { Menu, X } from 'lucide-react';
import { authService } from '../services/api';
import { useNavigate } from 'react-router-dom';

const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(window.innerWidth > 1024);
  const [isMobile, setIsMobile] = useState(window.innerWidth <= 1024);
  const navigate = useNavigate();

  useEffect(() => {
    // Safety check: if user data is missing but we're in a protected route layout, force logout
    if (!authService.isAuthenticated()) {
      authService.logout();
      navigate('/login');
      return;
    }

    const handleResize = () => {
      const mobile = window.innerWidth <= 1024;
      setIsMobile(mobile);
      if (mobile) {
        setIsSidebarOpen(false);
      } else {
        setIsSidebarOpen(true);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, [navigate]);

  const toggleSidebar = () => setIsSidebarOpen(!isSidebarOpen);

  return (
    <div style={{ display: 'flex', width: '100%', minHeight: '100vh', position: 'relative', overflow: 'hidden' }}>
      {/* Burger Button */}
      <button 
        onClick={toggleSidebar}
        className="burger-button"
        style={{
          position: 'fixed',
          top: '20px',
          left: '20px',
          zIndex: 1001,
          padding: '10px',
          backgroundColor: 'var(--card-bg)',
          backdropFilter: 'blur(12px)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          transition: 'all 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: 'var(--shadow-sm)',
          transform: isSidebarOpen && !isMobile ? 'translateX(260px)' : 'none'
        }}
        onMouseOver={e => { e.currentTarget.style.backgroundColor = 'var(--bg-color)'; e.currentTarget.style.boxShadow = 'var(--shadow-md)'; }}
        onMouseOut={e => { e.currentTarget.style.backgroundColor = 'var(--card-bg)'; e.currentTarget.style.boxShadow = 'var(--shadow-sm)'; }}
      >
        {isSidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Sidebar Overlay for Mobile */}
      {isSidebarOpen && isMobile && (
        <div 
          onClick={toggleSidebar}
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.7)',
            zIndex: 998,
            backdropFilter: 'blur(4px)',
            animation: 'fadeIn 0.2s ease-out'
          }}
        />
      )}

      <Sidebar isOpen={isSidebarOpen} isMobile={isMobile} />
      
      <main style={{
        flex: 1,
        minWidth: 0,
        height: '100vh',
        overflowY: 'auto',
        padding: isMobile ? '16px' : '32px',
        paddingTop: '80px',
        backgroundColor: 'var(--bg-color)',
        transition: 'all 0.4s cubic-bezier(0.16, 1, 0.3, 1)',
      }}>
        <div style={{ 
          maxWidth: '1600px', 
          margin: '0 auto',
          width: '100%',
          animation: 'fadeIn 0.4s ease-out'
        }}>
          {children}
        </div>
      </main>
    </div>
  );
};

export default Layout;
