interface MethodBadgeProps {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
}

const methodStyles = {
  GET: { color: '#16A34A', bg: 'rgba(22, 163, 74, 0.15)' },
  POST: { color: '#3B82F6', bg: 'rgba(59, 130, 246, 0.15)' },
  PUT: { color: '#EA580C', bg: 'rgba(234, 88, 12, 0.15)' },
  DELETE: { color: '#DC2626', bg: 'rgba(220, 38, 38, 0.15)' },
  PATCH: { color: '#CA8A04', bg: 'rgba(202, 138, 4, 0.15)' },
};

export function MethodBadge({ method }: MethodBadgeProps) {
  const style = methodStyles[method];

  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 8px',
        borderRadius: '4px',
        backgroundColor: style.bg,
        color: style.color,
        fontSize: '11px',
        fontWeight: '600',
        fontFamily: 'monospace',
        letterSpacing: '0.3px',
      }}
    >
      {method}
    </span>
  );
}
