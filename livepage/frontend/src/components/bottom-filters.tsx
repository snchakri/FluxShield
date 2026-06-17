import { Pause, Play, Search } from 'lucide-react';

interface BottomFiltersProps {
  isPaused: boolean;
  onTogglePause: () => void;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  selectedSeverity: string;
  onSeverityChange: (value: string) => void;
  selectedCountry: string;
  onCountryChange: (value: string) => void;
  countries: string[];
}

export function BottomFilters({
  isPaused,
  onTogglePause,
  searchQuery,
  onSearchChange,
  selectedSeverity,
  onSeverityChange,
  selectedCountry,
  onCountryChange,
  countries,
}: BottomFiltersProps) {
  const severityOptions = [
    { value: '', label: 'All Severities' },
    { value: 'critical', label: 'Critical' },
    { value: 'high', label: 'High' },
    { value: 'medium', label: 'Medium' },
    { value: 'low', label: 'Low' },
    { value: 'none', label: 'None' },
  ];

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '16px 20px',
        backgroundColor: '#111827',
        borderRadius: '8px',
        border: '1px solid #1F2937',
        marginTop: '16px',
      }}
    >
      {/* Left: Pause/Play Button */}
      <button
        onClick={onTogglePause}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          padding: '8px 16px',
          backgroundColor: isPaused ? '#3B82F6' : '#1F2937',
          color: '#E5E7EB',
          border: 'none',
          borderRadius: '6px',
          fontSize: '13px',
          fontWeight: '600',
          cursor: 'pointer',
          transition: 'background-color 0.15s',
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.backgroundColor = isPaused ? '#2563EB' : '#374151';
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.backgroundColor = isPaused ? '#3B82F6' : '#1F2937';
        }}
      >
        {isPaused ? <Play size={14} /> : <Pause size={14} />}
        <span>{isPaused ? 'Resume Stream' : 'Pause Stream'}</span>
      </button>

      {/* Center: Search */}
      <div style={{ position: 'relative', flex: '0 0 400px' }}>
        <Search
          size={16}
          style={{
            position: 'absolute',
            left: '12px',
            top: '50%',
            transform: 'translateY(-50%)',
            color: '#6B7280',
          }}
        />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search by IP, endpoint, or attack type..."
          style={{
            width: '100%',
            padding: '8px 12px 8px 36px',
            backgroundColor: '#0A0E1A',
            border: '1px solid #1F2937',
            borderRadius: '6px',
            color: '#E5E7EB',
            fontSize: '13px',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={(e) => {
            e.target.style.borderColor = '#3B82F6';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = '#1F2937';
          }}
        />
      </div>

      {/* Right: Dropdowns */}
      <div style={{ display: 'flex', gap: '12px' }}>
        <select
          value={selectedSeverity}
          onChange={(e) => onSeverityChange(e.target.value)}
          style={{
            padding: '8px 12px',
            backgroundColor: '#0A0E1A',
            border: '1px solid #1F2937',
            borderRadius: '6px',
            color: '#E5E7EB',
            fontSize: '13px',
            cursor: 'pointer',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={(e) => {
            e.target.style.borderColor = '#3B82F6';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = '#1F2937';
          }}
        >
          {severityOptions.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>

        <select
          value={selectedCountry}
          onChange={(e) => onCountryChange(e.target.value)}
          style={{
            padding: '8px 12px',
            backgroundColor: '#0A0E1A',
            border: '1px solid #1F2937',
            borderRadius: '6px',
            color: '#E5E7EB',
            fontSize: '13px',
            cursor: 'pointer',
            outline: 'none',
            transition: 'border-color 0.15s',
          }}
          onFocus={(e) => {
            e.target.style.borderColor = '#3B82F6';
          }}
          onBlur={(e) => {
            e.target.style.borderColor = '#1F2937';
          }}
        >
          <option value="">All Countries</option>
          {countries.map((country) => (
            <option key={country} value={country}>
              {country}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
