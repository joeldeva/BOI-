import React from 'react';
import { Clock, Loader2, CheckCircle2, XCircle, Ban } from 'lucide-react';
import type { JobStatus } from '../../types/api';

interface JobStatusBadgeProps {
  status: JobStatus;
  jobId?: string;
  errorMessage?: string | null;
  className?: string;
}

const STATUS_CONFIG: Record<JobStatus, { label: string; color: string; bg: string; Icon: React.FC<any> }> = {
  queued: {
    label: 'Queued',
    color: 'text-amber-400',
    bg: 'bg-amber-500/10 border-amber-500/30',
    Icon: Clock,
  },
  running: {
    label: 'Analyzing…',
    color: 'text-blue-400',
    bg: 'bg-blue-500/10 border-blue-500/30',
    Icon: Loader2,
  },
  completed: {
    label: 'Completed',
    color: 'text-emerald-400',
    bg: 'bg-emerald-500/10 border-emerald-500/30',
    Icon: CheckCircle2,
  },
  failed: {
    label: 'Failed',
    color: 'text-red-400',
    bg: 'bg-red-500/10 border-red-500/30',
    Icon: XCircle,
  },
  cancelled: {
    label: 'Cancelled',
    color: 'text-slate-400',
    bg: 'bg-slate-800/60 border-slate-700/30',
    Icon: Ban,
  },
};

export const JobStatusBadge: React.FC<JobStatusBadgeProps> = ({
  status,
  jobId,
  errorMessage,
  className = '',
}) => {
  const cfg = STATUS_CONFIG[status];
  const { Icon } = cfg;

  return (
    <div className={`space-y-1.5 ${className}`}>
      <div
        className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs font-semibold ${cfg.color} ${cfg.bg}`}
      >
        <Icon
          className={`w-3.5 h-3.5 shrink-0 ${status === 'running' ? 'animate-spin' : ''}`}
        />
        <span>{cfg.label}</span>
        {jobId && (
          <span className="font-mono text-[10px] opacity-60 ml-1">
            {jobId.slice(0, 14)}…
          </span>
        )}
      </div>
      {status === 'failed' && errorMessage && (
        <p className="text-xs text-red-300 font-mono pl-1 max-w-xs truncate" title={errorMessage}>
          {errorMessage}
        </p>
      )}
    </div>
  );
};
