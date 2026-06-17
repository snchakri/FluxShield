# WAF Live Traffic Monitoring - API Integration Guide

This document outlines how to integrate your backend API or WebSocket with the Live Traffic Monitoring dashboard.

## Overview

The dashboard is fully prepared for real-time data integration. All components are state-driven and ready to receive live data from your WAF backend.

## Data Structure

### Traffic Record Interface

```typescript
interface TrafficRecord {
  id: string;
  time: string;                    // Format: "HH:MM:SS" or "YYYY-MM-DD HH:MM:SS"
  ipAddress: string;               // IPv4 or IPv6
  country: string;                 // Country name or code
  endpoint: string;                // API endpoint or URL path
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  attackType: string;              // e.g., "SQL Injection", "XSS", "None"
  severity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  confidence: string;              // e.g., "95%", "High", "Medium"
  action: 'allowed' | 'blocked';
}
```

## Integration Points

### 1. Traffic Data Stream

**Location:** `/App.tsx` - Line 66-91

**Method 1: REST API Polling (Recommended for lower-frequency updates)**

```typescript
useEffect(() => {
  const fetchTrafficData = async () => {
    setIsLoading(true);
    try {
      const response = await fetch('https://your-api.com/api/traffic/live');
      const data = await response.json();
      setTrafficData(data);
    } catch (error) {
      console.error('Error fetching traffic data:', error);
    } finally {
      setIsLoading(false);
    }
  };

  fetchTrafficData();

  // Poll every 2 seconds (adjust as needed)
  const interval = setInterval(() => {
    if (!isPaused) {
      fetchTrafficData();
    }
  }, 2000);

  return () => clearInterval(interval);
}, [isPaused]);
```

**Method 2: WebSocket (Recommended for real-time streaming)**

```typescript
useEffect(() => {
  const ws = new WebSocket('wss://your-api.com/traffic/stream');
  
  ws.onopen = () => {
    console.log('WebSocket connected');
    setWebsocketStatus('connected');
  };
  
  ws.onmessage = (event) => {
    const newRecords = JSON.parse(event.data);
    setTrafficData(prevData => {
      const updated = [...newRecords, ...prevData];
      return updated.slice(0, 1000); // Keep last 1000 records
    });
  };
  
  ws.onerror = () => {
    setWebsocketStatus('disconnected');
  };
  
  ws.onclose = () => {
    setWebsocketStatus('disconnected');
  };

  return () => ws.close();
}, []);
```

### 2. Status Metrics

**Location:** `/App.tsx` - Line 93-102

**WebSocket Example:**

```typescript
useEffect(() => {
  const ws = new WebSocket('wss://your-api.com/metrics');
  
  ws.onmessage = (event) => {
    const metrics = JSON.parse(event.data);
    setRequestsPerSecond(metrics.requestsPerSecond);
    setLatency(metrics.latency);
    setServerHealth(metrics.serverHealth); // 'healthy' | 'degraded' | 'down'
  };

  return () => ws.close();
}, []);
```

**Expected Metrics Payload:**

```json
{
  "requestsPerSecond": 4287,
  "latency": "12ms",
  "serverHealth": "healthy"
}
```

## Features

### Automatic Row Limiting
- Dashboard automatically limits visible rows to **100 maximum**
- Filtering happens client-side on received data
- Scrolling enabled when data exceeds table height

### Pause/Resume Stream
- `isPaused` state controls data updates
- When paused, polling stops or WebSocket messages are ignored
- Toggle via bottom control bar

### Real-time Filtering
- **Search:** Filters by IP address, endpoint, or attack type
- **Severity:** Filters by severity level
- **Country:** Filters by country name
- All filters work instantly on received data

### Dynamic Row Count
- Shows "Showing X of Y records"
- Indicates when limited to 100 visible rows
- Updates automatically as data changes

## State Management

All data is managed through React state:

```typescript
const [trafficData, setTrafficData] = useState<TrafficRecord[]>([]);
const [isLoading, setIsLoading] = useState(false);
const [isPaused, setIsPaused] = useState(false);
const [websocketStatus, setWebsocketStatus] = useState<'connected' | 'disconnected'>('connected');
const [serverHealth, setServerHealth] = useState<'healthy' | 'degraded' | 'down'>('healthy');
const [requestsPerSecond, setRequestsPerSecond] = useState(0);
const [latency, setLatency] = useState('0ms');
```

## Error Handling

Implement proper error handling:

```typescript
try {
  const response = await fetch('/api/traffic/live');
  if (!response.ok) throw new Error('API error');
  const data = await response.json();
  setTrafficData(data);
} catch (error) {
  console.error('Error fetching traffic data:', error);
  // Optionally show error state in UI
}
```

## Performance Considerations

1. **Data Limiting:** Keep only necessary records in state (recommend max 1000)
2. **Polling Interval:** Adjust based on your traffic volume (2-5 seconds recommended)
3. **Debouncing:** Consider debouncing search input for better performance
4. **Memoization:** All filters use `useMemo` for optimal performance

## Testing

For testing without a backend, you can inject sample data:

```typescript
// Add this temporarily for testing
useEffect(() => {
  const sampleData: TrafficRecord[] = [
    {
      id: '1',
      time: '14:23:45',
      ipAddress: '192.168.1.100',
      country: 'United States',
      endpoint: '/api/v1/users',
      method: 'GET',
      attackType: 'None',
      severity: 'none',
      confidence: '99%',
      action: 'allowed'
    },
    // Add more sample records...
  ];
  
  setTrafficData(sampleData);
}, []);
```

## Security Notes

- Use WSS (WebSocket Secure) in production
- Implement authentication for API endpoints
- Validate and sanitize all incoming data
- Consider rate limiting on the backend
- Use HTTPS for all REST API calls

## Support

For issues or questions, refer to the main application documentation or contact your backend team.
