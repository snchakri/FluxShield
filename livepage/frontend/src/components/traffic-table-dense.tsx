import { MethodBadge } from './method-badge';
import { SeverityIndicator } from './severity-indicator';
import { ActionBadge } from './action-badge';

export interface TrafficRecord {
  id: string;
  time: string;
  ipAddress: string;
  country: string;
  endpoint: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  attackType: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  confidence: string;
  action: 'allowed' | 'blocked';
}

interface TrafficTableDenseProps {
  data: TrafficRecord[];
  isLoading?: boolean;
  totalRecords?: number;
}

export function TrafficTableDense({ data, isLoading = false, totalRecords = 0 }: TrafficTableDenseProps) {
  if (isLoading) {
    return (
      <div
        style={{
          backgroundColor: '#111827',
          border: '1px solid #1F2937',
          borderRadius: '8px',
          padding: '40px',
          textAlign: 'center',
        }}
      >
        <div
          style={{
            width: '32px',
            height: '32px',
            border: '3px solid #1F2937',
            borderTopColor: '#3B82F6',
            borderRadius: '50%',
            margin: '0 auto 12px',
            animation: 'spin 1s linear infinite',
          }}
        />
        <p style={{ color: '#9CA3AF', fontSize: '13px', margin: 0 }}>Loading traffic data...</p>
        <style>
          {`
            @keyframes spin {
              to { transform: rotate(360deg); }
            }
          `}
        </style>
      </div>
    );
  }

  return (
    <div
      style={{
        backgroundColor: '#111827',
        border: '1px solid #1F2937',
        borderRadius: '8px',
        overflow: 'hidden',
      }}
    >
      <div
        style={{
          maxHeight: '540px',
          overflowY: 'auto',
          overflowX: 'auto',
        }}
      >
        <table
          style={{
            width: '100%',
            borderCollapse: 'collapse',
            fontSize: '13px',
          }}
        >
          <thead
            style={{
              position: 'sticky',
              top: 0,
              backgroundColor: '#0A0E1A',
              zIndex: 10,
            }}
          >
            <tr>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  fontSize: '11px',
                  fontWeight: '600',
                  color: '#9CA3AF',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  borderBottom: '1px solid #1F2937',
                  width: '60px',
                }}
              >
                S.No
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Time
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                IP Address
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Country
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  minWidth: '200px',
                }}
              >
                Endpoint
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Method
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Attack Type
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Severity
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Confidence
              </th>
              <th
                style={{
                  padding: '12px 16px',
                  textAlign: 'left',
                  color: '#9CA3AF',
                  fontWeight: '600',
                  fontSize: '11px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.5px',
                  whiteSpace: 'nowrap',
                }}
              >
                Action
              </th>
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr>
                <td
                  colSpan={10}
                  style={{
                    padding: '64px 32px',
                    textAlign: 'center',
                  }}
                >
                  <p
                    style={{
                      color: '#6B7280',
                      fontSize: '13px',
                      margin: '0 0 8px 0',
                    }}
                  >
                    Waiting for live backend traffic...
                  </p>
                  <p
                    style={{
                      color: '#4B5563',
                      fontSize: '12px',
                      margin: 0,
                    }}
                  >
                    Connect backend API or WebSocket to populate data.
                  </p>
                </td>
              </tr>
            ) : (
              data.map((record, index) => (
                <tr
                  key={record.id}
                  style={{
                    borderBottom: '1px solid #1F2937',
                    cursor: 'pointer',
                    transition: 'background-color 0.1s',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.backgroundColor = 'rgba(59, 130, 246, 0.05)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.backgroundColor = 'transparent';
                  }}
                >
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#E5E7EB',
                      fontSize: '12px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {index + 1}
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#E5E7EB',
                      fontSize: '12px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.time}
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#E5E7EB',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.ipAddress}
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#9CA3AF',
                      fontSize: '12px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.country}
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#E5E7EB',
                      fontSize: '12px',
                      fontFamily: 'monospace',
                      maxWidth: '300px',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                    title={record.endpoint}
                  >
                    {record.endpoint}
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    <MethodBadge method={record.method} />
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#9CA3AF',
                      fontSize: '12px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.attackType}
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    <SeverityIndicator severity={record.severity} />
                  </td>
                  <td
                    style={{
                      padding: '10px 16px',
                      color: '#9CA3AF',
                      fontSize: '12px',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {record.confidence}
                  </td>
                  <td style={{ padding: '10px 16px' }}>
                    <ActionBadge action={record.action} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}