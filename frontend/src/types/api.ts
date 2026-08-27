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

export type AIExperimentType =
  | 'LAUNCH_APP'
  | 'OBSERVE_STARTUP'
  | 'SYNTHETIC_SMS'
  | 'NETWORK_OBSERVATION'
  | 'ACCESSIBILITY_OBSERVATION'
  | 'FILESYSTEM_DIFF'
  | 'DYNAMIC_CODE_LOAD_OBSERVATION'
  | 'WEBVIEW_OBSERVATION'
  | 'UI_SCREENSHOT'
  | 'PACKAGE_STATE_CAPTURE'
  | 'LOGCAT_CAPTURE';

export type AIExperimentStatus = 'PLANNED' | 'SKIPPED' | 'UNSUPPORTED' | 'UNAVAILABLE' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'TIMED_OUT';

export interface AIExperimentDefinition {
  experiment_type: AIExperimentType;
  description: string;
  required_capabilities: string[];
  timeout_seconds: number;
  safe_by_default: boolean;
  produces_evidence_types: string[];
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
    configured_enabled: boolean;
    adb_available: boolean;
    emulator_configured: boolean;
    emulator_serial: string | null;
    safe_target_shape: boolean;
    runtime_ready: boolean;
    readiness: {
      ready: boolean;
      checks: JsonObject;
      reasons: string[];
      probe_timeout_seconds: number;
    };
    frida: JsonObject;
    observers_enabled: JsonObject;
    network_policy?: JsonObject;
  };
  llm: {
    provider: 'disabled' | 'openai' | 'gemini' | string;
    configured: boolean;
    ready: boolean;
    model: string | null;
    reason: string;
    controls_risk_score: false;
  };
  ai_experiments: {
    catalog_version: string;
    plan_limit: number;
    max_investigation_rounds: number;
    max_experiments_per_round: number;
    execution_mode: 'planned-only' | string;
    catalog: AIExperimentDefinition[];
  };
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
  base_points?: number;
  rationale: string;
  required_evidence?: string;
  evidence_ids?: string[];
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
  status: 'completed' | 'disabled' | 'unavailable' | 'failed' | 'timeout' | 'blocked-by-policy';
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

export type AIInvestigationStatus = 'disabled' | 'completed' | 'failed' | 'unavailable';
export type AIHypothesisStatus = 'PROPOSED' | 'SUPPORTED' | 'CONTRADICTED' | 'CONFIRMED' | 'INCONCLUSIVE';
export type AIHypothesisCategory =
  | 'OTP_INTERCEPTION'
  | 'ACCESSIBILITY_ABUSE'
  | 'CREDENTIAL_PHISHING'
  | 'OVERLAY_ATTACK'
  | 'DATA_EXFILTRATION'
  | 'DYNAMIC_CODE_LOADING'
  | 'DEVICE_RECONNAISSANCE'
  | 'BANK_IMPERSONATION'
  | 'REMOTE_CONTROL'
  | 'UNKNOWN_SUSPICIOUS_BEHAVIOR';

export interface InvestigationEvidenceItem {
  evidence_id: string;
  evidence_type: string;
  source: string;
  title: string;
  value: string;
  confidence: number;
  phase?: string;
  trust_level?: string;
  source_engine?: string | null;
  source_artifact?: string | null;
  class_name?: string | null;
  method_name?: string | null;
  call_site?: string | null;
  code_context?: string | null;
  code_ownership?: string;
  timestamp_ms?: number | null;
  metadata: JsonObject;
}

export interface AIHypothesis {
  hypothesis_id: string;
  category: AIHypothesisCategory;
  status: AIHypothesisStatus;
  confidence: number;
  title: string;
  reasoning_summary: string;
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  missing_evidence: string[];
  recommended_experiment_types: AIExperimentType[];
  recommended_next_steps: string[];
  limitations: string[];
  evidence_strength: number;
  verification_summary: string;
  runtime_evidence_ids: string[];
}

export interface AIExperimentPlanItem {
  experiment_id: string;
  hypothesis_id: string;
  experiment_type: AIExperimentType;
  objective: string;
  expected_signal: string;
  priority: number;
  status: AIExperimentStatus;
  description: string;
  required_capabilities: string[];
  timeout_seconds: number;
  safe_by_default: boolean;
  produces_evidence_types: string[];
  supported: boolean;
  unsupported_reason: string | null;
}

export interface HypothesisVerification {
  hypothesis_id: string;
  category: AIHypothesisCategory | string;
  original_status: AIHypothesisStatus | string;
  verified_status: AIHypothesisStatus | string;
  evidence_strength: number;
  ai_confidence: number;
  static_evidence_ids: string[];
  runtime_evidence_ids: string[];
  experiment_result_ids: string[];
  observed_signals: string[];
  missing_signals: string[];
  deterministic_explanation: string;
  confirmation_allowed: boolean;
}

export interface AIInvestigation {
  schema_version: string;
  provider: string;
  model: string;
  status: AIInvestigationStatus;
  hypotheses: AIHypothesis[];
  experiment_plan: AIExperimentPlanItem[];
  hypothesis_verifications: HypothesisVerification[];
  feedback_loop: {
    rounds_completed: number;
    round_limit: number;
    max_experiments_per_round: number;
    stopped_reason: string;
    [key: string]: unknown;
  };
  evidence_count: number;
  evidence: InvestigationEvidenceItem[];
  controls_risk_score: false;
  can_mark_malicious: false;
  warning: string | null;
  validation_errors: string[];
}

export interface RuntimeEvidence {
  evidence_id: string;
  timestamp_ms: number;
  evidence_type: string;
  source: 'dynamic' | string;
  trust_level?: 'INFERRED' | 'LOG_OBSERVED' | 'SYSTEM_OBSERVED' | 'INSTRUMENTED' | 'PAYLOAD_CORRELATED' | string;
  process: string;
  description: string;
  confidence: number;
  metadata: JsonObject;
}

export interface DynamicExperimentResult {
  experiment_id: string;
  experiment_type: AIExperimentType;
  status: AIExperimentStatus;
  started_at_ms: number;
  completed_at_ms: number;
  evidence_ids: string[];
  summary: string;
  unavailable_reason: string | null;
  error: string | null;
  metadata: JsonObject;
}

export interface PayloadLineageStep {
  step_index: number;
  evidence_id: string;
  phase: 'INGRESS' | 'TRANSFORMATION' | 'INTERNAL_STATE' | 'EGRESS' | string;
  api: string;
  transform_type: string;
  matched_value: string;
  description: string;
}

export interface PayloadLineage {
  lineage_id: string;
  marker_id: string;
  marker_type: string;
  marker_value: string;
  evidence_chain: string[];
  steps: PayloadLineageStep[];
  source_evidence_id: string;
  sink_evidence_id: string | null;
  is_complete_exfiltration: boolean;
  trust_level: string;
  summary: string;
}

export interface RecoveredPayload {
  payload_id: string;
  parent_sample_sha256: string;
  sha256: string;
  payload_type: 'DEX' | 'JAR' | 'UNKNOWN';
  size_bytes: number;
  source: string;
  loader: string;
  runtime_evidence_id?: string | null;
  storage_reference?: string | null;
  analysis_status: 'ANALYZED' | 'UNAVAILABLE' | 'INVALID_MAGIC' | 'OVERSIZED' | 'FAILED';
  extracted_capabilities: string[];
  method_level_evidence?: JsonObject[];
  metadata?: JsonObject;
}

export interface FraudDNAFingerprint {
  apk_sha256: string;
  app_identity: string;
  package_name: string;
  app_label: string;
  signer_fingerprints: string[];
  icon_phash?: string | null;
  dex_fingerprints: string[];
  dex_fuzzy_hash?: string | null;
  behavior_signatures: string[];
  permissions: string[];
  banking_capabilities: string[];
  domains: string[];
  urls: string[];
  ips: string[];
  firebase_project_ids: string[];
  recovered_payload_hashes: string[];
}

export interface RelatedSample {
  sha256: string;
  similarity: number;
  reasons: string[];
  campaign_id?: string | null;
  app_label?: string | null;
  package_name?: string | null;
}

export interface Campaign {
  campaign_id: string;
  name: string;
  member_sha256s: string[];
  primary_signatures: string[];
  shared_infrastructure: string[];
  shared_firebase_projects: string[];
  shared_signer_fingerprints: string[];
  created_at?: string | null;
}

export interface FirebaseInfrastructure {
  project_id?: string | null;
  mobilesdk_app_id?: string | null;
  firebase_url?: string | null;
  storage_bucket?: string | null;
  gcm_defaultSenderId?: string | null;
  api_key?: string | null;
  database_urls: string[];
  firestore_collections: string[];
  raw_config_detected: boolean;
  source: string;
}

export type BrandImpersonationVerdict =
  | 'VERY_HIGH'
  | 'HIGH'
  | 'SUSPICIOUS'
  | 'NONE'
  | 'OFFICIAL_LEGITIMATE'
  | 'NOT_CONFIGURED';  // No bank reference profiles loaded — cannot evaluate

export interface BrandImpersonationResult {
  target_bank_id?: string | null;
  target_bank_name?: string | null;
  app_label_similarity: number;
  package_name_similarity: number;
  icon_similarity?: number | null;
  is_official_package: boolean;
  is_trusted_signer: boolean;
  domain_similarity: number;
  brand_keywords_detected: string[];
  has_credential_forms: boolean;
  impersonation_score: number;
  verdict: BrandImpersonationVerdict;
  reasons: string[];
  /** 'CONFIGURED' | 'NOT_CONFIGURED' — whether trusted signer inventory is loaded */
  signer_reference_status?: string;
  /** 'CONFIGURED' | 'NOT_CONFIGURED' — whether reference icon phash is loaded */
  icon_reference_status?: string;
}

export type BankingImpactStatus = 'CONFIRMED' | 'SUPPORTED' | 'POSSIBLE' | 'NOT_OBSERVED';

export interface BankingImpactItem {
  id: string;
  category: string;
  title: string;
  description: string;
  status: BankingImpactStatus;
  deterministic_basis: string;
  evidence_ids: string[];
  signals: string[];
}

export interface BankingImpact {
  items: BankingImpactItem[];
  summary: Record<string, number>;
}

export interface ApkAnalysisResult {
  schema_version: string;
  analysis_id: string;
  decision_notice: string;
  malware_assessment: MalwareAssessment;
  engine_analysis: EngineAnalysis;
  risk: {
    overall_score: number;
    static_score?: number;
    runtime_adjustment?: number;
    runtime_confirmation?: number;
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
    static_rules?: ApkRiskEvidence[];
    runtime_rules?: ApkRiskEvidence[];
    evidence: ApkRiskEvidence[];
  };
  fraud_delta: FraudDelta;
  mitre_attack: MitreAttackItem[];
  emitted_indicators: ThreatIndicatorRecord[];
  runtime_evidence: RuntimeEvidence[];
  experiment_results: DynamicExperimentResult[];
  payload_lineage?: PayloadLineage[];
  recovered_payloads?: RecoveredPayload[];
  frauddna?: FraudDNAFingerprint;
  related_samples?: RelatedSample[];
  campaign?: Campaign;
  brand_impersonation?: BrandImpersonationResult;
  firebase_infrastructure?: FirebaseInfrastructure;
  banking_impact?: BankingImpact;
  extraction: ApkExtractionDetails;
  ai_investigation?: AIInvestigation;
  narrative_metadata: { llm_controls_score: false; source: string; warning: string | null };
}

export interface ApkAnalysisRecord {
  id: string;
  analysis_id?: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  data_origin: DataOrigin;
  file_name: string;
  package_name?: string | null;
  app_name?: string | null;
  sha256: string;
  size_bytes: number;
  category: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  static_score?: number | null;
  runtime_adjustment?: number | null;
  overall_score: number | null;
  severity: SeverityLevel | null;
  confidence: number | null;
  analysis_quality: AnalysisQuality | null;
  dynamic_status?: string | null;
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
