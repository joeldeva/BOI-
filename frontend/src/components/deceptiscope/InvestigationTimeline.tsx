import { useState, useMemo } from 'react';
import {
  ArrowRight,
  BrainCircuit,
  CheckCircle2,
  CircleDot,
  Copy,
  Cpu,
  Eye,
  FileSearch,
  Globe,
  HelpCircle,
  Package,
  ShieldAlert,
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
  color: string;
  bgColor: string;
  borderColor: string;
  label: string;
  badgeLabel?: string;
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
    label: 'STATIC EVIDENCE',
  },
  engine: {
    icon: Cpu,
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-500',
    borderColor: 'border-cyan-500/40',
    label: 'ENGINE FINDINGS',
  },
  ai: {
    icon: BrainCircuit,
    color: 'text-violet-400',
    bgColor: 'bg-violet-500',
    borderColor: 'border-violet-500/40',
    label: 'AI HYPOTHESIS',
    badgeLabel: 'AI PROPOSAL (NON-AUTHORITATIVE)',
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
    label: 'DETERMINISTIC VERIFICATION',
    badgeLabel: 'DETERMINISTIC PROOF (AUTHORITATIVE)',
  },
  scoring: {
    icon: CircleDot,
    color: 'text-red-400',
    bgColor: 'bg-red-500',
    borderColor: 'border-red-500/40',
    label: 'RISK ASSESSMENT',
  },
};

/* ---------- status styling ---------- */
const STATUS_STYLE: Record<string, string> = {
  // Honest unrun / failed states
  NOT_RUN: 'text-slate-400 border-slate-700 bg-slate-900/60',
  SKIPPED: 'text-slate-400 border-slate-700 bg-slate-900/60',
  UNSUPPORTED: 'text-amber-400 border-amber-500/40 bg-amber-950/30',
  UNAVAILABLE: 'text-amber-400 border-amber-500/40 bg-amber-950/30',
  BLOCKED: 'text-red-400 border-red-500/40 bg-red-950/30',
  FAILED: 'text-red-400 border-red-500/40 bg-red-950/30 font-bold',
  TIMED_OUT: 'text-amber-400 border-amber-500/40 bg-amber-950/30',
  INCONCLUSIVE: 'text-amber-300 border-amber-500/40 bg-amber-950/30 font-medium',

  // Running & completed
  PLANNED: 'text-blue-300 border-blue-500/30 bg-blue-950/20',
  RUNNING: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
  COMPLETED: 'text-emerald-300 border-emerald-500/40 bg-emerald-950/20 font-medium',

  // Verification & Trust levels
  PROPOSED: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
  SUPPORTED: 'text-blue-300 border-blue-500/40 bg-blue-950/30 font-medium',
  CONFIRMED: 'text-emerald-300 border-emerald-500/50 bg-emerald-950/40 font-bold shadow-[0_0_10px_rgba(16,185,129,0.15)]',
  CONTRADICTED: 'text-red-300 border-red-500/40 bg-red-950/30 font-medium',

  // Provenance trust levels
  PAYLOAD_CORRELATED: 'text-cyan-300 border-cyan-500/50 bg-cyan-950/40 font-bold',
  INSTRUMENTED: 'text-emerald-300 border-emerald-500/40 bg-emerald-950/30 font-medium',
  SYSTEM_OBSERVED: 'text-blue-300 border-blue-500/30 bg-blue-950/20',
  LOG_OBSERVED: 'text-slate-300 border-slate-600 bg-slate-900/50',
  INFERRED: 'text-violet-300 border-violet-500/30 bg-violet-950/20',
};

/* ---------- confidence & strength bar ---------- */
function MetricBar({ value, label, isAi }: { value: number; label: string; isAi?: boolean }) {
  const pct = Math.round(value * 100);
  let barColor = isAi ? 'bg-violet-500' : 'bg-emerald-500';
  if (pct >= 85) barColor = isAi ? 'bg-violet-400' : 'bg-red-500';
  else if (pct >= 50) barColor = isAi ? 'bg-violet-500' : 'bg-amber-500';
  else if (pct >= 25) barColor = 'bg-blue-500';

  return (
    <div className="flex items-center gap-2 mt-1.5 min-w-0">
      <span className="text-[10px] text-slate-500 uppercase font-bold shrink-0">{label}</span>
      <div className="flex-1 h-1.5 rounded-full bg-slate-800 overflow-hidden max-w-[100px]">
        <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] font-mono font-bold text-slate-300">{pct}%</span>
    </div>
  );
}

/* ---------- interactive provenance chip ---------- */
function ProvenanceChip({ id, type }: { id: string; type?: 'evidence' | 'hypothesis' | 'experiment' | 'rule' }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(id).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  let colorClasses = 'bg-blue-500/10 text-blue-300 border-blue-500/20 hover:bg-blue-500/20';
  if (type === 'hypothesis' || id.startsWith('H')) {
    colorClasses = 'bg-violet-500/10 text-violet-300 border-violet-500/20 hover:bg-violet-500/20';
  } else if (type === 'experiment' || id.startsWith('EXP') || id.startsWith('DYN')) {
    colorClasses = 'bg-cyan-500/10 text-cyan-300 border-cyan-500/20 hover:bg-cyan-500/20';
  } else if (type === 'rule' || id.startsWith('RUNTIME-') || id.startsWith('APK-')) {
    colorClasses = 'bg-red-500/10 text-red-300 border-red-500/20 hover:bg-red-500/20';
  } else if (id.startsWith('R') || id.startsWith('RT')) {
    colorClasses = 'bg-emerald-500/10 text-emerald-300 border-emerald-500/20 hover:bg-emerald-500/20';
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={`Click to copy ID: ${id}`}
      className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded border text-[10px] font-mono transition-colors cursor-pointer ${colorClasses}`}
    >
      <span>{id}</span>
      {copied ? <span className="text-[9px] text-emerald-400">✓</span> : <Copy className="w-2.5 h-2.5 opacity-50" />}
    </button>
  );
}

/* ---------- single timeline node ---------- */
function TimelineNode({ event, isLast }: { event: InvestigationEvent; isLast: boolean }) {
  const config = PHASE_CONFIG[event.phase];
  const Icon = config.icon;

  const isConfirmed = event.status === 'CONFIRMED';
  const isContradicted = event.status === 'CONTRADICTED';
  const isInconclusive = event.status === 'INCONCLUSIVE';
  const isFailed = event.status === 'FAILED' || event.status === 'BLOCKED';

  return (
    <div className="timeline-node relative flex gap-3 md:gap-4" data-phase={event.phase}>
      {/* Vertical line + dot */}
      <div className="flex flex-col items-center shrink-0 w-8 md:w-10">
        <div className={`w-7 h-7 md:w-8 md:h-8 rounded-full flex items-center justify-center border-2 ${config.borderColor} bg-slate-950 z-10 shrink-0`}>
          <Icon className={`w-3.5 h-3.5 md:w-4 md:h-4 ${config.color}`} />
        </div>
        {!isLast && (
          <div className="timeline-connector flex-1 w-px bg-slate-700/60 min-h-[24px]" />
        )}
      </div>

      {/* Content card */}
      <div className="flex-1 pb-5 min-w-0">
        {/* Phase Header */}
        <div className="flex flex-wrap items-center gap-2">
          <span className={`text-[9px] md:text-[10px] font-bold uppercase tracking-widest ${config.color} opacity-90`}>
            {config.label}
          </span>
          {event.isAiGenerated && (
            <span className="px-1.5 py-0.2 rounded bg-violet-950/60 border border-violet-500/30 text-[9px] font-mono text-violet-300">
              AI PROPOSAL · NON-AUTHORITATIVE
            </span>
          )}
          {event.phase === 'verification' && (
            <span className="px-1.5 py-0.2 rounded bg-emerald-950/60 border border-emerald-500/30 text-[9px] font-mono text-emerald-300">
              DETERMINISTIC PROOF · AUTHORITATIVE
            </span>
          )}
        </div>

        {/* Title row */}
        <div className="flex flex-wrap items-center gap-2 mt-0.5">
          <h4 className="text-xs md:text-sm font-bold text-white leading-tight break-words">{event.title}</h4>
          {event.status && (
            <span className={`px-1.5 py-0.5 rounded border text-[9px] font-mono uppercase shrink-0 ${STATUS_STYLE[event.status] ?? 'text-slate-300 border-slate-700 bg-slate-950/40'}`}>
              {event.status}
            </span>
          )}
          {event.phase === 'verification' && (
            isConfirmed ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            ) : isContradicted ? (
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : isInconclusive ? (
              <HelpCircle className="w-4 h-4 text-amber-400 shrink-0" />
            ) : null
          )}
          {isFailed && <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />}
        </div>

        {/* Description */}
        {event.description && (
          <p className="text-xs text-slate-300 leading-relaxed mt-1 break-words">{event.description}</p>
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

        {/* Provenance Links */}
        <div className="mt-2 flex flex-wrap items-center gap-1.5">
          {event.hypothesisId && (
            <ProvenanceChip id={event.hypothesisId} type="hypothesis" />
          )}
          {event.experimentId && (
            <ProvenanceChip id={event.experimentId} type="experiment" />
          )}
          {event.evidenceIds && event.evidenceIds.map((eid) => (
            <ProvenanceChip key={eid} id={eid} type="evidence" />
          ))}
          {event.scoringRules && event.scoringRules.map((rid) => (
            <ProvenanceChip key={rid} id={rid} type="rule" />
          ))}
        </div>

        {/* AI Confidence vs Deterministic Evidence Strength */}
        <div className="flex flex-wrap gap-4 mt-1">
          {event.confidence != null && event.phase !== 'scoring' && (
            <MetricBar value={event.confidence} label={event.isAiGenerated ? "ai confidence" : "confidence"} isAi={event.isAiGenerated} />
          )}
          {event.evidenceStrength != null && (
            <MetricBar value={event.evidenceStrength} label="deterministic strength" isAi={false} />
          )}
        </div>

        {/* Deterministic Scoring Breakdown Card */}
        {event.phase === 'scoring' && event.scoreTo != null && (
          <div className="mt-3 p-3 rounded-lg border border-slate-800 bg-slate-900/60 space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="text-[11px] font-mono text-slate-400 font-bold uppercase tracking-wider">
                Model: apk-risk-2026.5
              </span>
              {event.severity && (
                <span className={`soc-badge ${event.severity === 'CRITICAL' ? 'soc-badge-critical' : event.severity === 'HIGH' ? 'soc-badge-high' : event.severity === 'MEDIUM' ? 'soc-badge-medium' : 'soc-badge-low'} text-[10px]`}>
                  <span className="w-1.5 h-1.5 rounded-full bg-current" />
                  {event.severity}
                </span>
              )}
            </div>

            {event.runtimeAdjustment != null && event.runtimeAdjustment > 0 && event.scoreFrom != null && event.scoreFrom !== event.scoreTo ? (
              <div className="flex items-center gap-3 md:gap-4 flex-wrap">
                <ScoreGauge score={event.scoreFrom} size={76} strokeWidth={6} label="STATIC" />
                <div className="flex flex-col items-center justify-center px-2 py-1 rounded bg-red-950/40 border border-red-500/30">
                  <div className="flex items-center gap-1 text-red-400 font-mono font-bold text-xs">
                    <span>+{event.runtimeAdjustment}</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-[8px] font-mono text-red-300 uppercase tracking-tight">Verified Egress</span>
                </div>
                <ScoreGauge score={event.scoreTo} size={76} strokeWidth={6} label="FINAL FRAUD" />
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <ScoreGauge score={event.scoreTo} size={76} strokeWidth={6} label="FINAL FRAUD" />
                <div className="text-xs text-slate-400 font-mono">
                  Static risk confirmed without runtime escalation (adjustment: 0 pts)
                </div>
              </div>
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
          <div className="flex flex-col items-center shrink-0 w-8 md:w-10">
            <div className="w-7 h-7 md:w-8 md:h-8 rounded-full bg-slate-800 border-2 border-slate-700" />
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
        Enable the LLM provider and dynamic sandbox capabilities to see the end-to-end investigation timeline
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

  const hasInvestigation = result?.ai_investigation && result.ai_investigation.status !== 'disabled';
  const hasRuntimeEvidence = (result?.runtime_evidence ?? []).length > 0;
  const hasExperimentResults = (result?.experiment_results ?? []).length > 0;
  const showTimeline = events.length > 2 || hasInvestigation || hasRuntimeEvidence || hasExperimentResults;

  return (
    <section className="soc-card p-4 md:p-6 space-y-4">
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
        <div className="timeline-container space-y-1">
          {events.map((event, index) => (
            <TimelineNode key={event.id} event={event} isLast={index === events.length - 1} />
          ))}
        </div>
      )}
    </section>
  );
}
