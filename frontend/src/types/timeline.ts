import type {
  ApkAnalysisResult,
  AIInvestigation,
  SeverityLevel,
} from './api';

export type InvestigationPhase =
  | 'ingestion'
  | 'static'
  | 'ai'
  | 'experiment'
  | 'runtime'
  | 'network'
  | 'verification'
  | 'scoring';

export interface InvestigationEvent {
  id: string;
  phase: InvestigationPhase;
  title: string;
  description?: string;
  details?: string[];
  evidenceIds?: string[];
  hypothesisId?: string;
  experimentId?: string;
  status?: string;
  confidence?: number;
  scoreFrom?: number;
  scoreTo?: number;
  severity?: SeverityLevel | string;
}

/* ---------- phase ordering for chronological sort ---------- */
const PHASE_ORDER: Record<InvestigationPhase, number> = {
  ingestion: 0,
  static: 1,
  ai: 2,
  experiment: 3,
  runtime: 4,
  network: 5,
  verification: 6,
  scoring: 7,
};

/* ---------- builder helpers ---------- */
let _seq = 0;
function nextId(prefix: string): string {
  return `${prefix}-${++_seq}`;
}

function resetSeq(): void {
  _seq = 0;
}

function addIngestionEvents(result: ApkAnalysisResult, events: InvestigationEvent[]): void {
  const app = result.extraction?.app;
  const fileName = app?.app_label || app?.package_name || 'APK';
  events.push({
    id: nextId('ingest'),
    phase: 'ingestion',
    title: 'APK Received',
    description: `${fileName} submitted for analysis`,
    details: [
      app?.package_name ? `Package: ${app.package_name}` : '',
      app?.version_name ? `Version: ${app.version_name}` : '',
      app?.target_sdk ? `Target SDK: ${app.target_sdk}` : '',
    ].filter(Boolean),
  });
}

function addStaticEvents(result: ApkAnalysisResult, events: InvestigationEvent[]): void {
  const extraction = result.extraction;
  if (!extraction) return;

  const components = extraction.components;
  const permissions = extraction.permissions;
  const codeSignals = extraction.code_signals;

  /* Flagged dangerous permissions */
  const dangerous = permissions?.flagged_dangerous ?? [];
  if (dangerous.length > 0) {
    events.push({
      id: nextId('static'),
      phase: 'static',
      title: 'Dangerous Permissions Detected',
      description: `${dangerous.length} flagged permission${dangerous.length > 1 ? 's' : ''} discovered`,
      details: dangerous.map((p) => p.replace('android.permission.', '')),
    });
  }

  /* Component capabilities */
  const capabilities: string[] = [];
  if (components?.sms_receiver) capabilities.push('SMS Receiver declared');
  if (components?.accessibility_service) capabilities.push('Accessibility Service declared');
  if (components?.boot_receiver) capabilities.push('Boot Receiver declared');
  if (capabilities.length > 0) {
    events.push({
      id: nextId('static'),
      phase: 'static',
      title: 'Suspicious Components Discovered',
      description: capabilities.join(' · '),
      details: capabilities,
    });
  }

  /* Code signals */
  if (codeSignals) {
    const detected = Object.entries(codeSignals)
      .filter(([, signal]) => signal.detected)
      .map(([name, signal]) => ({
        name: name.replaceAll('_', ' '),
        evidence: signal.evidence,
      }));
    if (detected.length > 0) {
      events.push({
        id: nextId('static'),
        phase: 'static',
        title: 'Code Signal Analysis',
        description: `${detected.length} suspicious code pattern${detected.length > 1 ? 's' : ''} identified`,
        details: detected.map((d) => `${d.name}: ${d.evidence.join(', ')}`),
      });
    }
  }
}

function addAIHypothesisEvents(investigation: AIInvestigation, events: InvestigationEvent[]): void {
  for (const hypothesis of investigation.hypotheses) {
    events.push({
      id: nextId('ai'),
      phase: 'ai',
      title: hypothesis.title,
      description: hypothesis.reasoning_summary,
      hypothesisId: hypothesis.hypothesis_id,
      confidence: hypothesis.confidence,
      status: hypothesis.status,
      evidenceIds: hypothesis.supporting_evidence_ids,
    });
  }
}

function addExperimentEvents(investigation: AIInvestigation, events: InvestigationEvent[]): void {
  for (const experiment of investigation.experiment_plan) {
    events.push({
      id: nextId('exp'),
      phase: 'experiment',
      title: experiment.experiment_type.replaceAll('_', ' '),
      description: experiment.objective,
      experimentId: experiment.experiment_id,
      hypothesisId: experiment.hypothesis_id,
      status: experiment.status,
    });
  }
}

function addRuntimeEvents(result: ApkAnalysisResult, events: InvestigationEvent[]): void {
  const runtimeEvidence = result.runtime_evidence ?? [];
  for (const evidence of runtimeEvidence) {
    const isNetwork = evidence.evidence_type.toLowerCase().includes('network') ||
                      evidence.evidence_type.toLowerCase().includes('outbound');
    events.push({
      id: nextId(isNetwork ? 'net' : 'rt'),
      phase: isNetwork ? 'network' : 'runtime',
      title: evidence.description || evidence.evidence_type,
      description: evidence.process ? `Process: ${evidence.process}` : undefined,
      confidence: evidence.confidence,
      status: evidence.source,
    });
  }

  /* Experiment results that produced runtime observations */
  const experimentResults = result.experiment_results ?? [];
  for (const expResult of experimentResults) {
    if (expResult.status !== 'COMPLETED' && expResult.status !== 'FAILED') continue;
    const isNetwork = expResult.experiment_type === 'NETWORK_OBSERVATION';
    events.push({
      id: nextId(isNetwork ? 'net' : 'rt'),
      phase: isNetwork ? 'network' : 'runtime',
      title: expResult.summary || expResult.experiment_type.replaceAll('_', ' '),
      experimentId: expResult.experiment_id,
      status: expResult.status,
      evidenceIds: expResult.evidence_ids,
    });
  }
}

function addVerificationEvents(investigation: AIInvestigation, events: InvestigationEvent[]): void {
  const verifications = investigation.hypothesis_verifications ?? [];
  for (const verification of verifications) {
    const isConfirmed = verification.verified_status === 'CONFIRMED';
    const isContradicted = verification.verified_status === 'CONTRADICTED';
    events.push({
      id: nextId('verify'),
      phase: 'verification',
      title: isConfirmed
        ? 'Hypothesis Confirmed'
        : isContradicted
          ? 'Hypothesis Contradicted'
          : `Hypothesis ${verification.verified_status}`,
      description: verification.deterministic_explanation,
      hypothesisId: verification.hypothesis_id,
      status: verification.verified_status as string,
      confidence: verification.ai_confidence,
      evidenceIds: [
        ...verification.static_evidence_ids,
        ...verification.runtime_evidence_ids,
        ...verification.experiment_result_ids,
      ],
    });
  }
}

function addScoringEvents(result: ApkAnalysisResult, events: InvestigationEvent[]): void {
  const risk = result.risk;
  if (!risk) return;

  /* Calculate static-only baseline score (before fraud_delta adjustment) */
  const fraudDeltaAdjustment = risk.fraud_delta_adjustment ?? 0;
  const staticScore = Math.max(0, Math.round(risk.overall_score - fraudDeltaAdjustment));
  const finalScore = risk.overall_score;

  events.push({
    id: nextId('score'),
    phase: 'scoring',
    title: 'Risk Assessment Complete',
    description: staticScore !== finalScore
      ? `Evidence escalated risk from ${staticScore} to ${finalScore}`
      : `Final risk score: ${finalScore}`,
    scoreFrom: staticScore,
    scoreTo: finalScore,
    severity: risk.severity,
    confidence: risk.confidence,
  });
}

/* ---------- main builder ---------- */
export function buildTimelineEvents(result: ApkAnalysisResult | null | undefined): InvestigationEvent[] {
  if (!result) return [];

  resetSeq();
  const events: InvestigationEvent[] = [];

  addIngestionEvents(result, events);
  addStaticEvents(result, events);

  const investigation = result.ai_investigation;
  if (investigation && investigation.status !== 'disabled') {
    addAIHypothesisEvents(investigation, events);
    addExperimentEvents(investigation, events);
  }

  addRuntimeEvents(result, events);

  if (investigation && investigation.status !== 'disabled') {
    addVerificationEvents(investigation, events);
  }

  addScoringEvents(result, events);

  /* Stable chronological sort by phase order, preserving insertion order within phase */
  events.sort((a, b) => PHASE_ORDER[a.phase] - PHASE_ORDER[b.phase]);

  return events;
}
