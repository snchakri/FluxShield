import { Shield, LayoutDashboard, Activity, Brain, BarChart3, Settings, FileText, LogOut, BookOpen } from 'lucide-react';

interface SidebarProps {
  activeItem?: string;
}

export function Sidebar({ activeItem = 'live-traffic' }: SidebarProps) {
  const menuItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'live-traffic', label: 'Live Traffic', icon: Activity },
    { id: 'threat-intelligence', label: 'Threat Intelligence', icon: Shield },
    { id: 'attack-analytics', label: 'Attack Analytics', icon: BarChart3 },
    { id: 'adaptive-learning', label: 'Adaptive Learning', icon: Brain },
    { id: 'rules-policies', label: 'Rules & Policies', icon: BookOpen },
    { id: 'logs-reports', label: 'Logs & Reports', icon: FileText },
    { id: 'settings', label: 'Settings', icon: Settings },
  ];

  return (
    <div
      style={{
        width: '240px',
        height: '100vh',
        backgroundColor: '#0D1117',
        borderRight: '1px solid #1F2937',
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        left: 0,
        top: 0,
      }}
    >
      {/* Logo */}
      <div
        style={{
          padding: '20px 16px',
          borderBottom: '1px solid #1F2937',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
        }}
      >
        <div
          style={{
            width: '32px',
            height: '32px',
            backgroundColor: '#3B82F6',
            borderRadius: '6px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
          }}
        >
          <Shield size={20} style={{ color: '#FFFFFF' }} />
        </div>
        <span
          style={{
            fontSize: '16px',
            fontWeight: '700',
            color: '#E5E7EB',
          }}
        >
          SecureWAF
        </span>
      </div>

      {/* Menu Items */}
      <nav style={{ flex: 1, padding: '16px 0', overflowY: 'auto' }}>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = item.id === activeItem;

          return (
            <button
              key={item.id}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                gap: '12px',
                padding: '10px 16px',
                border: 'none',
                backgroundColor: isActive ? 'rgba(59, 130, 246, 0.1)' : 'transparent',
                color: isActive ? '#3B82F6' : '#9CA3AF',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: isActive ? '600' : '500',
                transition: 'all 0.15s',
                borderLeft: isActive ? '3px solid #3B82F6' : '3px solid transparent',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.05)';
                  e.currentTarget.style.color = '#E5E7EB';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = '#9CA3AF';
                }
              }}
            >
              <Icon size={18} />
              <span>{item.label}</span>
            </button>
          );
        })}
      </nav>

      {/* Logout */}
      <div style={{ padding: '16px', borderTop: '1px solid #1F2937' }}>
        <button
          style={{
            width: '100%',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            padding: '10px 16px',
            border: 'none',
            backgroundColor: 'transparent',
            color: '#9CA3AF',
            cursor: 'pointer',
            fontSize: '14px',
            fontWeight: '500',
            transition: 'all 0.15s',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = 'rgba(220, 38, 38, 0.1)';
            e.currentTarget.style.color = '#DC2626';
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent';
            e.currentTarget.style.color = '#9CA3AF';
          }}
        >
          <LogOut size={18} />
          <span>Logout</span>
        </button>
      </div>
    </div>
  );
}
