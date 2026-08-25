import { useMemo } from 'react';
import {
  ArrowDown,
  BrainCircuit,
  CheckCircle2,
  CircleDot,
  Eye,
  FileSearch,
  Globe,
  HelpCircle,
  Package,
  ShieldCheck,
  XCircle,
  Zap,
} from 'lucide-react';
import { ScoreGauge } from '../common/ScoreGauge';
import type { ApkAnalysisResult } from '../../types/api';
import { buildTimelineEvents, type InvestigationEvent, type InvestigationPhase } from '../../types/timeline';

/* ---------- phase visual config ---------- */
interface PhaseConfig {
  icon: React.ComponentType<{ className?: string }>;
  color: string;        /* tailwind text color */
  bgColor: string;      /* tailwind bg for node dot */
  borderColor: string;  /* tailwind border for line accent */
  label: string;
}

const PHASE_CONFIG: Record<InvestigationPhase, PhaseConfig> = {
  ingestion: {
    icon: Package,
    color: 'text-blue-400',
    bgColor: 'bg-blue-500',
    borderColor: 'border-blue-500/40',
    label: 'INGESTION',
  },
  static: {
    icon: FileSearch,
    color: 'text-amber-400',
    bgColor: 'bg-amber-500',
    borderColor: 'border-amber-500/40',
    label: 'STATIC ANALYSIS',
  },
  ai: {
    icon: BrainCircuit,
    color: 'text-violet-400',
    bgColor: 'bg-violet-500',
    borderColor: 'border-violet-500/40',
    label: 'AI HYPOTHESIS',
  },
  experiment: {
    icon: Zap,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-500',
    borderColor: 'border-cyan-500/40',
    label: 'EXPERIMENT',
  },
  runtime: {
    icon: Eye,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-500',
    borderColor: 'border-emerald-500/40',
    label: 'RUNTIME OBSERVATION',
  },
  network: {
    icon: Globe,
    color: 'text-rose-400',
    bgColor: 'bg-rose-500',
    borderColor: 'border-rose-500/40',
    label: 'NETWORK OBSERVATION',
  },
  verification: {
    icon: ShieldCheck,
    color: 'text-emerald-400',
    bgColor: 'bg-emerald-500',
    borderColor: 'border-emerald-500/40',
    label: 'VERIFICATION',
  },
  scoring: {
    icon: CircleDot,
    color: 'text-red-400',
    bgColor: 'bg-red-500',
    borderColor: 'border-red-500/40',
    label: 'SCORING',
  },
};

/* ---------- experiment status styling (reused from ApkAnalysisView) ---------- */
const STATUS_STYLE: Record<string, string> = {
  PLANNED: 'text-blue-300 border-blue-500/30 bg-blue-950/20',
  SKIPPED: 'text-slate-300 border-slate-700 bg-slate-950/40',
  UNSUPPORTED: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  UNAVAILABLE: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  RUNNING: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
  COMPLETED: 'text-emerald-300 border-emerald-500/30 bg-emerald-950/20',
  FAILED: 'text-red-300 border-red-500/30 bg-red-950/20',
  TIMED_OUT: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
  PROPOSED: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
  SUPPORTED: 'text-blue-300 border-blue-500/30 bg-blue-950/20',
  CONFIRMED: 'text-emerald-300 border-emerald-500/30 bg-emerald-950/20',
  CONTRADICTED: 'text-red-300 border-red-500/30 bg-red-950/20',
  INCONCLUSIVE: 'text-amber-300 border-amber-500/30 bg-amber-950/20',
};

/* ---------- confidence bar ---------- */
function ConfidenceBar({ confidence, label }: { confidence: number; label?: string }) {
  const pct = Math.round(confidence * 100);
  let barColor = 'bg-emerald-500';
  if (pct >= 75) barColor = 'bg-red-500';
  else if (pct >= 50) barColor = 'bg-amber-500';
  else if (pct >= 25) barColor = 'bg-blue-500';

  return (
    <div className="flex items-center gap-2 mt-1.5">
      {label && <span className="text-[10px] text-slate-500 uppercase font-bold shrink-0">{label}</span>}
      <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden max-w-[120px]">
        <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] font-mono font-bold text-slate-300">{pct}%</span>
    </div>
  );
}

/* ---------- single timeline node ---------- */
function TimelineNode({ event, isLast }: { event: InvestigationEvent; isLast: boolean }) {
  const config = PHASE_CONFIG[event.phase];
  const Icon = config.icon;

  const isConfirmed = event.status === 'CONFIRMED';
  const isContradicted = event.status === 'CONTRADICTED';

  return (
    <div className="timeline-node relative flex gap-4" data-phase={event.phase}>
      {/* Vertical line + dot */}
      <div className="flex flex-col items-center shrink-0 w-10">
        <div className={`w-8 h-8 rounded-full flex items-center justify-center border-2 ${config.borderColor} bg-slate-950 z-10`}>
          <Icon className={`w-4 h-4 ${config.color}`} />
        </div>
        {!isLast && (
          <div className="timeline-connector flex-1 w-px bg-slate-700/60 min-h-[24px]" />
        )}
      </div>

      {/* Content card */}
      <div className={`flex-1 pb-5 ${isLast ? '' : ''}`}>
        {/* Phase label */}
        <span className={`text-[9px] font-bold uppercase tracking-widest ${config.color} opacity-80`}>
          {config.label}
        </span>

        {/* Title row */}
        <div className="flex flex-wrap items-start gap-2 mt-0.5">
          <h4 className="text-sm font-bold text-white leading-tight">{event.title}</h4>
          {event.status && (
            <span className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-bold uppercase ${STATUS_STYLE[event.status] ?? 'text-slate-300 border-slate-700 bg-slate-950/40'}`}>
              {event.status}
            </span>
          )}
          {event.phase === 'verification' && (
            isConfirmed
              ? <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              : isContradicted
                ? <XCircle className="w-4 h-4 text-red-400 shrink-0" />
                : <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
          )}
        </div>

        {/* Description */}
        {event.description && (
          <p className="text-xs text-slate-400 leading-relaxed mt-1">{event.description}</p>
        )}

        {/* Details list */}
        {event.details && event.details.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {event.details.map((detail) => (
              <span key={detail} className="px-1.5 py-0.5 rounded bg-slate-800/80 border border-slate-700/60 text-[10px] font-mono text-slate-300">
                {detail}
              </span>
            ))}
          </div>
        )}

        {/* Evidence IDs */}
        {event.evidenceIds && event.evidenceIds.length > 0 && (
          <div className="mt-1.5 flex flex-wrap gap-1">
            {event.evidenceIds.map((eid) => (
              <span
                key={eid}
                className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px] font-mono cursor-pointer hover:bg-blue-500/20 transition-colors"
                title={`Evidence: ${eid}`}
              >
                {eid}
              </span>
            ))}
          </div>
        )}

        {/* Hypothesis / experiment IDs */}
        <div className="flex flex-wrap gap-2 mt-1">
          {event.hypothesisId && (
            <span className="text-[10px] font-mono text-violet-400 opacity-70">{event.hypothesisId}</span>
          )}
          {event.experimentId && (
            <span className="text-[10px] font-mono text-cyan-400 opacity-70">{event.experimentId}</span>
          )}
        </div>

        {/* Confidence */}
        {event.confidence != null && event.phase !== 'scoring' && (
          <ConfidenceBar confidence={event.confidence} label="confidence" />
        )}

        {/* Score transition */}
        {event.phase === 'scoring' && event.scoreFrom != null && event.scoreTo != null && (
          <div className="mt-3 flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-3">
              <ScoreGauge score={event.scoreFrom} size={80} strokeWidth={7} label="STATIC" />
              <div className="flex flex-col items-center gap-0.5">
                <ArrowDown className="w-5 h-5 text-slate-500" />
                <span className="text-[9px] font-mono text-slate-600">delta</span>
              </div>
              <ScoreGauge score={event.scoreTo} size={80} strokeWidth={7} label="FINAL" />
            </div>
            {event.severity && (
              <span className={`soc-badge ${event.severity === 'CRITICAL' ? 'soc-badge-critical' : event.severity === 'HIGH' ? 'soc-badge-high' : event.severity === 'MEDIUM' ? 'soc-badge-medium' : 'soc-badge-low'} text-[10px]`}>
                <span className="w-1.5 h-1.5 rounded-full bg-current" />
                {event.severity}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* ---------- skeleton / loading ---------- */
function TimelineSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      {[1, 2, 3].map((i) => (
        <div key={i} className="flex gap-4">
          <div className="flex flex-col items-center shrink-0 w-10">
            <div className="w-8 h-8 rounded-full bg-slate-800 border-2 border-slate-700" />
            {i < 3 && <div className="flex-1 w-px bg-slate-800 min-h-[24px]" />}
          </div>
          <div className="flex-1 pb-5 space-y-2">
            <div className="h-2 w-20 rounded bg-slate-800" />
            <div className="h-3.5 w-48 rounded bg-slate-800" />
            <div className="h-2.5 w-64 rounded bg-slate-800" />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ---------- empty state ---------- */
function TimelineEmpty() {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-center">
      <BrainCircuit className="w-10 h-10 text-slate-600 mb-3" />
      <p className="text-sm font-bold text-slate-400">AI-driven investigation was not enabled</p>
      <p className="text-xs text-slate-500 mt-1 max-w-sm">
        Enable the LLM provider and dynamic analysis capabilities to see the full investigation timeline
      </p>
    </div>
  );
}

/* ---------- main component ---------- */
interface InvestigationTimelineProps {
  result: ApkAnalysisResult | null | undefined;
  loading?: boolean;
}

export function InvestigationTimeline({ result, loading }: InvestigationTimelineProps) {
  const events = useMemo(() => buildTimelineEvents(result), [result]);

  /* Only show if there's meaningful investigation data beyond basic ingestion+scoring */
  const hasInvestigation = result?.ai_investigation && result.ai_investigation.status !== 'disabled';
  const hasRuntimeEvidence = (result?.runtime_evidence ?? []).length > 0;
  const hasExperimentResults = (result?.experiment_results ?? []).length > 0;
  const showTimeline = events.length > 2 || hasInvestigation || hasRuntimeEvidence || hasExperimentResults;

  return (
    <section className="soc-card p-6 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-5 h-5 text-violet-400" />
          <h3 className="text-base font-bold text-white">Investigation Timeline</h3>
        </div>
        {events.length > 0 && (
          <span className="text-[11px] font-mono text-slate-400">
            {events.length} events · {new Set(events.map((e) => e.phase)).size} phases
          </span>
        )}
      </div>

      {loading ? (
        <TimelineSkeleton />
      ) : !showTimeline ? (
        <TimelineEmpty />
      ) : (
        <div className="timeline-container">
          {events.map((event, index) => (
            <TimelineNode key={event.id} event={event} isLast={index === events.length - 1} />
          ))}
        </div>
      )}
    </section>
  );
}
