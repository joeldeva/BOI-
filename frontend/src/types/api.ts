export type SeverityLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type DataOrigin = 'uploaded' | 'synthetic';
export type AnalysisQuality = 'full' | 'partial' | 'synthetic';
export type JsonObject = Record<string, unknown>;

export interface ApiErrorDetail {
  code: string;
  message: string;
  details?: JsonObject;
  request_id?: string;
}

export interface ApiErrorResponse { error: ApiErrorDetail; }

export interface HealthResponse {
  status: 'healthy' | 'degraded' | string;
  database: 'up' | 'down' | string;
  version: string;
}

export interface EngineCapability {
  id: string;
  label: string;
  enabled: boolean;
  available: boolean;
  mode: string;
}

export interface CapabilitiesResponse {
  static_apk_analysis: boolean;
  apk_only_product: true;
  multi_engine: {
    orchestrator_version: string;
    engines: EngineCapability[];
    binary_upload_policy: string;
    external_hash_lookups: boolean;
    mobsf_binary_transfer: boolean;
    notice: string;
  };
  dynamic_lite: {
    enabled: boolean;
    adb_available: boolean;
    emulator_serial_configured: boolean;
    safe_target_shape: boolean;
  };
  llm: { provider: string; configured: boolean; controls_risk_score: false };
  pdf_reports: boolean;
  durable_jobs: boolean;
  inline_analysis: boolean;
  database: string;
  authentication: string;
  tamper_evident_audit: boolean;
}

export interface CountSummary {
  total: number;
  completed: number;
  failed: number;
  critical?: number;
}

export interface JobCountSummary extends CountSummary {
  queued: number;
  running: number;
  cancelled: number;
  oldest_queued_age_seconds: number;
}

export interface DashboardSummaryResponse {
  apk_analyses: CountSummary;
  indicator_count: number;
  jobs: JobCountSummary;
}

export interface ApkRiskEvidence {
  rule_id: string;
  title: string;
  category: string;
  points: number;
  rationale: string;
  artifacts: string[];
  source_finding_id?: string;
}

export interface FraudDeltaContribution {
  kind: string;
  evidence: string;
  weight: number;
  reason: string;
}

export interface FraudDelta {
  score: number;
  category: string;
  baseline_version: string;
  model_version: string;
  is_anomalous: boolean;
  unexpected_permissions: string[];
  methodology_note?: string;
  contributions: FraudDeltaContribution[];
}

export interface MitreAttackItem {
  technique_id: string;
  name: string;
  source: string;
  evidence: string[];
}

export interface ThreatIndicatorRecord {
  id: string;
  type: string;
  normalized_value: string;
  display_value: string;
  severity: SeverityLevel;
  confidence: number;
  first_seen: string;
  last_seen: string;
  sightings_count: number;
  description: string;
  metadata: JsonObject;
}

export interface ExtractionSignal { detected: boolean; evidence: string[]; }

export interface ApkExtractionDetails {
  analysis_mode: string;
  analysis_quality: AnalysisQuality;
  engine: string;
  extractor_version: string;
  app: {
    app_label?: string;
    package_name?: string;
    version_name?: string;
    version_code?: string;
    min_sdk?: string;
    target_sdk?: string;
  };
  permissions: { requested: string[]; flagged_dangerous: string[] };
  components: {
    activities: string[];
    services: string[];
    receivers: string[];
    providers: string[];
    exported: JsonObject[];
    accessibility_service: boolean;
    boot_receiver: boolean;
    sms_receiver: boolean;
  };
  code_signals: Record<string, ExtractionSignal>;
  network_indicators: { domains: string[]; ips: string[]; urls: string[] };
  warnings: string[];
  coverage: Record<string, boolean>;
  [key: string]: unknown;
}

export interface NormalizedEngineFinding {
  id: string;
  engine: string;
  title: string;
  severity: string;
  confidence: number;
  risk_category: string;
  risk_points: number;
  evidence: string[];
  score_eligible: boolean;
}

export interface EngineRun {
  id: string;
  label: string;
  status: 'completed' | 'disabled' | 'unavailable' | 'failed' | 'blocked-by-policy';
  duration_ms: number;
  privacy: string;
  summary: JsonObject;
  error?: string;
}

export interface EngineAnalysis {
  schema_version: string;
  orchestrator_version: string;
  policy: {
    public_binary_uploads: false;
    external_hash_lookups: boolean;
    mobsf_binary_transfer: boolean;
    unknown_is_safe: false;
  };
  summary: {
    completed: number;
    unavailable_or_failed: number;
    normalized_finding_count: number;
    tracker_count: number;
  };
  engines: EngineRun[];
  normalized_findings: NormalizedEngineFinding[];
  reputation: {
    verdict: string;
    known_malicious: boolean;
    providers: JsonObject[];
    notice: string;
  };
  coverage_note: string;
}

export interface MalwareAssessment {
  verdict: 'KNOWN_MALICIOUS' | 'HIGH_RISK' | 'SUSPICIOUS' | 'INCONCLUSIVE' | 'LOW_RISK_OBSERVED' | 'REVIEW_REQUIRED';
  known_malware: boolean;
  legitimacy: 'not-established';
  explanation: string;
  optional_engine_gaps: number;
  safe_to_install: false;
  limitations: string[];
}

export interface ApkAnalysisResult {
  schema_version: string;
  analysis_id: string;
  decision_notice: string;
  malware_assessment: MalwareAssessment;
  engine_analysis: EngineAnalysis;
  risk: {
    overall_score: number;
    severity: SeverityLevel;
    confidence: number;
    model_version: string;
    methodology_note: string;
    fraud_delta_adjustment: number;
    external_engine_evidence_count: number;
    sub_scores: {
      credential_theft: number;
      payment_manipulation: number;
      fraud_impersonation: number;
      evasion_resilience: number;
    };
    evidence: ApkRiskEvidence[];
  };
  fraud_delta: FraudDelta;
  mitre_attack: MitreAttackItem[];
  emitted_indicators: ThreatIndicatorRecord[];
  extraction: ApkExtractionDetails;
  narrative_metadata: { llm_controls_score: false; source: string; warning: string | null };
}

export interface ApkAnalysisRecord {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  data_origin: DataOrigin;
  file_name: string;
  sha256: string;
  size_bytes: number;
  category: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  overall_score: number | null;
  severity: SeverityLevel | null;
  confidence: number | null;
  analysis_quality: AnalysisQuality | null;
  narrative?: string | null;
  error_code: string | null;
  error_message: string | null;
  result?: ApkAnalysisResult | null;
}

export interface NewIndicatorPayload {
  type: string;
  value: string;
  severity: SeverityLevel;
  confidence: number;
  description?: string;
  metadata?: JsonObject;
}

export interface DemoSeedResponse {
  status: 'demo_seeded';
  data_origin: 'synthetic';
  apk_analysis_id: string;
  apk_risk: { score: number; severity: SeverityLevel };
  malware_assessment: MalwareAssessment;
  engine_summary: EngineAnalysis['summary'];
  notice: string;
}

export type JobStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type JobType = 'apk_analysis';

export interface JobResult {
  analysis_id?: string;
  status?: string;
  resource?: string;
}

export interface JobRecord {
  id: string;
  kind: JobType;
  status: JobStatus;
  payload: JsonObject;
  created_by: string;
  created_at: string;
  available_at: string;
  started_at: string | null;
  completed_at: string | null;
  attempts: number;
  max_attempts: number;
  priority: number;
  idempotency_key: string | null;
  result: JobResult | null;
  error_code: string | null;
  error_message: string | null;
  links: { self: string };
}

export interface SubmitApkJobParams {
  file: File;
  category?: 'banking' | 'finance' | 'utility' | 'other';
  dynamic?: boolean;
  priority?: number;
  maxAttempts?: number;
  idempotencyKey?: string;
}
