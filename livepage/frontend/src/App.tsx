import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import { TrafficTableDense, TrafficRecord } from './components/traffic-table-dense';
import { BottomFilters } from './components/bottom-filters';
import { StatusBar } from './components/status-bar';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface RuntimeMetrics {
  websocketStatus: 'connected' | 'disconnected';
  serverHealth: 'healthy' | 'degraded' | 'down';
  requestsPerSecond: number;
  latency: string;
  model: {
    mode: string;
    modelLoaded: boolean;
    teacherForced: boolean;
    driftScore: number;
    teacherFallbacks: number;
    learnerQueueSize: number;
    learnerTrained: number;
    learnerQuarantined: number;
    learnerAccepted: number;
    onlineUpdates: number;
    safetyBlocked: number;
  };
  storage: {
    fileDbHealthy: boolean;
    trafficRecordsRecent: number;
    securityAuditRecent: number;
  };
}

export default function App() {
  // State for backend API test
  const [backendMessage, setBackendMessage] = useState<string | null>(null);

  // State for filters
  const [isPaused, setIsPaused] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('');
  const [selectedCountry, setSelectedCountry] = useState('');

  // State for traffic data (API-ready)
  const [trafficData, setTrafficData] = useState<TrafficRecord[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [runtimeMetrics, setRuntimeMetrics] = useState<RuntimeMetrics | null>(null);

  // Test backend API connection
  useEffect(() => {
    // Function to fetch data from backend
    const testBackendConnection = async () => {
      try {
        // Send GET request to backend API
        const response = await axios.get(`${API_BASE_URL}/api/test`);
        
        // Log the entire response data to console
        console.log(response.data);
        
        // Store the message in state
        setBackendMessage(response.data.message);
      } catch (error) {
        // Log any errors
        console.error('Error connecting to backend:', error);
        setBackendMessage('Error connecting to backend');
      }
    };

    // Call the function when component loads
    testBackendConnection();
  }, []); // Empty dependency array means this runs once on mount

  // Extract unique countries from data
  const countries = useMemo(() => {
    const uniqueCountries = new Set(trafficData.map((record) => record.country));
    return Array.from(uniqueCountries).sort();
  }, [trafficData]);

  // Filter data based on current filter state
  const filteredData = useMemo(() => {
    let filtered = trafficData;

    // Search filter (IP, Endpoint, or Attack Type)
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase();
      filtered = filtered.filter(
        (record) =>
          record.ipAddress.toLowerCase().includes(query) ||
          record.endpoint.toLowerCase().includes(query) ||
          record.attackType.toLowerCase().includes(query)
      );
    }

    // Severity filter
    if (selectedSeverity) {
      filtered = filtered.filter((record) => record.severity === selectedSeverity);
    }

    // Country filter
    if (selectedCountry) {
      filtered = filtered.filter((record) => record.country === selectedCountry);
    }

    // Limit to 100 rows maximum
    return filtered.slice(0, 100);
  }, [trafficData, searchQuery, selectedSeverity, selectedCountry]);

  // Live traffic polling
  useEffect(() => {
    const fetchTrafficData = async () => {
      setIsLoading(true);
      try {
        const [trafficResponse, metricsResponse] = await Promise.all([
          axios.get(`${API_BASE_URL}/api/traffic/live`),
          axios.get(`${API_BASE_URL}/api/traffic/metrics`),
        ]);

        const records = trafficResponse.data?.records;

        if (Array.isArray(records)) {
          setTrafficData(records as TrafficRecord[]);
        } else {
          setTrafficData([]);
        }

        setRuntimeMetrics(metricsResponse.data as RuntimeMetrics);
      } catch (error) {
        console.error('Error fetching traffic data:', error);
      } finally {
        setIsLoading(false);
      }
    };

    if (!isPaused) {
      fetchTrafficData();
    }

    const interval = setInterval(() => {
      if (!isPaused) {
        fetchTrafficData();
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [isPaused]);

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0A0E1A' }}>
      {/* Main Content */}
      <div
        style={{
          maxWidth: '1600px',
          margin: '0 auto',
          padding: '32px 40px',
        }}
      >
        {/* Page Title */}
        <h1
          style={{
            margin: '0 0 8px 0',
            fontSize: '24px',
            fontWeight: '700',
            color: '#E5E7EB',
          }}
        >
          Live Traffic Monitoring
        </h1>
        
        {/* Subtitle */}
        <p
          style={{
            margin: '0 0 28px 0',
            fontSize: '14px',
            color: '#9CA3AF',
          }}
        >
          Real-time request and attack visibility
        </p>

        {/* Backend Connection Status */}
        <div
          style={{
            padding: '16px 20px',
            backgroundColor: '#111827',
            borderRadius: '8px',
            border: '1px solid #1F2937',
            marginBottom: '20px',
          }}
        >
          <h2
            style={{
              margin: '0 0 8px 0',
              fontSize: '16px',
              fontWeight: '600',
              color: '#E5E7EB',
            }}
          >
            Backend Connection Test
          </h2>
          <p
            style={{
              margin: 0,
              fontSize: '14px',
              color: backendMessage === 'API Works' ? '#10B981' : '#9CA3AF',
              fontWeight: '500',
            }}
          >
            {backendMessage === null ? 'Loading...' : backendMessage}
          </p>
        </div>

        <StatusBar
          websocketStatus={runtimeMetrics?.websocketStatus || 'disconnected'}
          serverHealth={runtimeMetrics?.serverHealth || 'degraded'}
          requestsPerSecond={runtimeMetrics?.requestsPerSecond || 0}
          latency={runtimeMetrics?.latency || 'n/a'}
        />

        {/* Runtime Summary */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
            gap: '12px',
            marginBottom: '14px',
          }}
        >
          {[
            {
              label: 'Adaptive Queue',
              value: String(runtimeMetrics?.model?.learnerQueueSize ?? 0),
              sub: `Accepted ${runtimeMetrics?.model?.learnerAccepted ?? 0} • Applied ${runtimeMetrics?.model?.onlineUpdates ?? 0}`,
            },
            {
              label: 'Drift Score',
              value: `${(runtimeMetrics?.model?.driftScore ?? 0).toFixed(3)}`,
              sub: `Teacher forced: ${(runtimeMetrics?.model?.teacherForced ?? false) ? 'yes' : 'no'}`,
            },
            {
              label: 'File DB Health',
              value: (runtimeMetrics?.storage?.fileDbHealthy ?? false) ? 'healthy' : 'degraded',
              sub: `Audit events ${runtimeMetrics?.storage?.securityAuditRecent ?? 0}`,
            },
            {
              label: 'Traffic Records',
              value: String(runtimeMetrics?.storage?.trafficRecordsRecent ?? 0),
              sub: `Fallbacks ${runtimeMetrics?.model?.teacherFallbacks ?? 0}`,
            },
          ].map((item) => (
            <div
              key={item.label}
              style={{
                padding: '12px 14px',
                backgroundColor: '#111827',
                borderRadius: '8px',
                border: '1px solid #1F2937',
              }}
            >
              <p style={{ margin: '0 0 6px 0', fontSize: '11px', color: '#9CA3AF', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {item.label}
              </p>
              <p style={{ margin: '0 0 4px 0', fontSize: '16px', color: '#E5E7EB', fontWeight: '700' }}>{item.value}</p>
              <p style={{ margin: 0, fontSize: '12px', color: '#9CA3AF' }}>{item.sub}</p>
            </div>
          ))}
        </div>

        {/* Traffic Table */}
        <TrafficTableDense data={filteredData} isLoading={isLoading} totalRecords={trafficData.length} />

        {/* Row Count Indicator */}
        <div
          style={{
            padding: '12px 20px',
            backgroundColor: '#111827',
            borderRadius: '8px',
            border: '1px solid #1F2937',
            marginTop: '12px',
          }}
        >
          <p
            style={{
              margin: 0,
              fontSize: '12px',
              color: '#9CA3AF',
            }}
          >
            {filteredData.length > 0 ? (
              <>
                Showing <span style={{ color: '#E5E7EB', fontWeight: '600' }}>{filteredData.length}</span> of{' '}
                <span style={{ color: '#E5E7EB', fontWeight: '600' }}>{trafficData.length}</span> records
                {trafficData.length > 100 && ' (limited to 100 visible rows)'}
              </>
            ) : (
              'No records to display'
            )}
          </p>
        </div>

        {/* Bottom Filters */}
        <BottomFilters
          isPaused={isPaused}
          onTogglePause={() => setIsPaused(!isPaused)}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          selectedSeverity={selectedSeverity}
          onSeverityChange={setSelectedSeverity}
          selectedCountry={selectedCountry}
          onCountryChange={setSelectedCountry}
          countries={countries}
        />
      </div>
    </div>
  );
}