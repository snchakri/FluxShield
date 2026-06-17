interface SeverityIndicatorProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
}

const severityConfig = {
  critical: { label: 'Critical', color: '#DC2626' },
  high: { label: 'High', color: '#EA580C' },
  medium: { label: 'Medium', color: '#CA8A04' },
  low: { label: 'Low', color: '#3B82F6' },
  none: { label: 'None', color: '#6B7280' },
};

export function SeverityIndicator({ severity }: SeverityIndicatorProps) {
  const config = severityConfig[severity];

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: '6px',
      }}
    >
      <div
        style={{
          width: '6px',
          height: '6px',
          borderRadius: '50%',
          backgroundColor: config.color,
        }}
      />
      <span style={{ fontSize: '12px', color: '#E5E7EB' }}>{config.label}</span>
    </div>
  );
}
