interface ActionBadgeProps {
  action: 'allowed' | 'blocked';
}

export function ActionBadge({ action }: ActionBadgeProps) {
  const isAllowed = action === 'allowed';

  return (
    <span
      style={{
        display: 'inline-block',
        padding: '3px 10px',
        borderRadius: '12px',
        backgroundColor: isAllowed ? 'rgba(22, 163, 74, 0.15)' : 'rgba(220, 38, 38, 0.15)',
        color: isAllowed ? '#16A34A' : '#DC2626',
        fontSize: '11px',
        fontWeight: '600',
      }}
    >
      {isAllowed ? 'Allowed' : 'Blocked'}
    </span>
  );
}
