import { type ReactNode } from 'react';

export type StatusVariant =
  | 'critical' | 'high' | 'medium' | 'low'
  | 'confirmed' | 'ready' | 'completed'
  | 'supported' | 'muted' | 'notconfigured'
  | 'unavailable' | 'disabled' | 'blue' | 'running'
  | 'suspicious' | 'suspected';

interface StatusPillProps {
  variant: StatusVariant;
  children: ReactNode;
  id?: string;
}

const variantClass: Record<StatusVariant, string> = {
  critical:     'status-critical',
  high:         'status-high',
  medium:       'status-medium',
  low:          'status-low',
  confirmed:    'status-confirmed',
  ready:        'status-ready',
  completed:    'status-completed',
  supported:    'status-supported',
  muted:        'status-muted',
  notconfigured:'status-notconfigured',
  unavailable:  'status-unavailable',
  disabled:     'status-disabled',
  blue:         'status-blue',
  running:      'status-running',
  suspicious:   'status-suspicious',
  suspected:    'status-suspected',
};

export function toVariant(s: string): StatusVariant {
  const v = s.toLowerCase().replace(/[\s_-]/g, '');
  if (v === 'critical' || v === 'knownmalicious') return 'critical';
  if (v === 'highrisk' || v === 'high') return 'high';
  if (v === 'medium') return 'medium';
  if (v === 'low' || v === 'lowriskobserved') return 'low';
  if (v === 'confirmed') return 'confirmed';
  if (v === 'ready') return 'ready';
  if (v === 'completed') return 'completed';
  if (v === 'supported') return 'supported';
  if (v === 'notconfigured') return 'notconfigured';
  if (v === 'unavailable') return 'unavailable';
  if (v === 'disabled' || v === 'skipped') return 'disabled';
  if (v === 'running') return 'running';
  if (v === 'suspicious' || v === 'suspected') return 'suspicious';
  return 'muted';
}

export function StatusPill({ variant, children, id }: StatusPillProps) {
  return (
    <span id={id} className={`status-pill ${variantClass[variant]}`} role="status">
      {children}
    </span>
  );
}

export function StatusPillAuto({ value, id }: { value: string; id?: string }) {
  return <StatusPill id={id} variant={toVariant(value)}>{value.replace(/_/g, ' ')}</StatusPill>;
}
