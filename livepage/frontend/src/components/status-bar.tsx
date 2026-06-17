import { Wifi, Activity, Zap, Clock } from 'lucide-react';

interface StatusBarProps {
  websocketStatus?: 'connected' | 'disconnected';
  serverHealth?: 'healthy' | 'degraded' | 'down';
  requestsPerSecond?: number;
  latency?: string;
}

export function StatusBar({
  websocketStatus = 'connected',
  serverHealth = 'healthy',
  requestsPerSecond = 0,
  latency = '12ms',
}: StatusBarProps) {
  const statusItems = [
    {
      icon: Wifi,
      label: 'WebSocket',
      value: websocketStatus === 'connected' ? 'Connected' : 'Disconnected',
      color: websocketStatus === 'connected' ? '#16A34A' : '#DC2626',
      showDot: true,
    },
    {
      icon: Activity,
      label: 'Server Health',
      value: serverHealth.charAt(0).toUpperCase() + serverHealth.slice(1),
      color: serverHealth === 'healthy' ? '#16A34A' : '#EA580C',
      showDot: false,
    },
    {
      icon: Zap,
      label: 'Requests/sec',
      value: requestsPerSecond.toLocaleString(),
      color: '#3B82F6',
      showDot: false,
    },
    {
      icon: Clock,
      label: 'Latency',
      value: latency,
      color: '#9CA3AF',
      showDot: false,
    },
  ];

  return (
    <div
      style={{
        display: 'flex',
        gap: '16px',
        padding: '12px 20px',
        backgroundColor: '#111827',
        borderRadius: '8px',
        border: '1px solid #1F2937',
        marginBottom: '20px',
      }}
    >
      {statusItems.map((item, index) => {
        const Icon = item.icon;
        return (
          <div
            key={index}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              paddingRight: index < statusItems.length - 1 ? '16px' : '0',
              borderRight: index < statusItems.length - 1 ? '1px solid #1F2937' : 'none',
            }}
          >
            <Icon size={14} style={{ color: item.color }} />
            <span style={{ fontSize: '12px', color: '#9CA3AF', fontWeight: '500' }}>
              {item.label}:
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              {item.showDot && (
                <div
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    backgroundColor: item.color,
                  }}
                />
              )}
              <span style={{ fontSize: '12px', color: item.color, fontWeight: '600' }}>
                {item.value}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}
