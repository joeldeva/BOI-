import test from 'node:test';
import assert from 'node:assert/strict';

/**
 * Since the builder is TypeScript, we test the logic by inlining
 * the pure function here in vanilla JS (mirroring the TS implementation).
 * This avoids needing a TS compilation step for `node --test`.
 */

const PHASE_ORDER = {
  ingestion: 0, static: 1, ai: 2, experiment: 3,
  runtime: 4, network: 5, verification: 6, scoring: 7,
};

const VALID_PHASES = new Set(Object.keys(PHASE_ORDER));

let _seq = 0;
function nextId(prefix) { return `${prefix}-${++_seq}`; }
function resetSeq() { _seq = 0; }

function buildTimelineEvents(result) {
  if (!result) return [];
  resetSeq();
  const events = [];

  // Ingestion
  const app = result.extraction?.app;
  const fileName = app?.app_label || app?.package_name || 'APK';
  events.push({
    id: nextId('ingest'), phase: 'ingestion', title: 'APK Received',
    description: `${fileName} submitted for analysis`,
    details: [
      app?.package_name ? `Package: ${app.package_name}` : '',
      app?.version_name ? `Version: ${app.version_name}` : '',
      app?.target_sdk ? `Target SDK: ${app.target_sdk}` : '',
    ].filter(Boolean),
  });

  // Static
  const extraction = result.extraction;
  if (extraction) {
    const dangerous = extraction.permissions?.flagged_dangerous ?? [];
    if (dangerous.length > 0) {
      events.push({
        id: nextId('static'), phase: 'static', title: 'Dangerous Permissions Detected',
        description: `${dangerous.length} flagged permission${dangerous.length > 1 ? 's' : ''} discovered`,
        details: dangerous.map(p => p.replace('android.permission.', '')),
      });
    }
    const capabilities = [];
    if (extraction.components?.sms_receiver) capabilities.push('SMS Receiver declared');
    if (extraction.components?.accessibility_service) capabilities.push('Accessibility Service declared');
    if (extraction.components?.boot_receiver) capabilities.push('Boot Receiver declared');
    if (capabilities.length > 0) {
      events.push({
        id: nextId('static'), phase: 'static', title: 'Suspicious Components Discovered',
        description: capabilities.join(' · '), details: capabilities,
      });
    }
    if (extraction.code_signals) {
      const detected = Object.entries(extraction.code_signals)
        .filter(([, s]) => s.detected).map(([name, s]) => ({
          name: name.replaceAll('_', ' '), evidence: s.evidence,
        }));
      if (detected.length > 0) {
        events.push({
          id: nextId('static'), phase: 'static', title: 'Code Signal Analysis',
          description: `${detected.length} suspicious code pattern${detected.length > 1 ? 's' : ''} identified`,
          details: detected.map(d => `${d.name}: ${d.evidence.join(', ')}`),
        });
      }
    }
  }

  // AI
  const investigation = result.ai_investigation;
  if (investigation && investigation.status !== 'disabled') {
    for (const h of investigation.hypotheses) {
      events.push({
        id: nextId('ai'), phase: 'ai', title: h.title, description: h.reasoning_summary,
        hypothesisId: h.hypothesis_id, confidence: h.confidence, status: h.status,
        evidenceIds: h.supporting_evidence_ids,
      });
    }
    for (const exp of investigation.experiment_plan) {
      events.push({
        id: nextId('exp'), phase: 'experiment',
        title: exp.experiment_type.replaceAll('_', ' '), description: exp.objective,
        experimentId: exp.experiment_id, hypothesisId: exp.hypothesis_id, status: exp.status,
      });
    }
  }

  // Runtime
  for (const ev of (result.runtime_evidence ?? [])) {
    const isNet = ev.evidence_type.toLowerCase().includes('network') ||
                  ev.evidence_type.toLowerCase().includes('outbound');
    events.push({
      id: nextId(isNet ? 'net' : 'rt'), phase: isNet ? 'network' : 'runtime',
      title: ev.description || ev.evidence_type,
      description: ev.process ? `Process: ${ev.process}` : undefined,
      confidence: ev.confidence, status: ev.source,
    });
  }
  for (const er of (result.experiment_results ?? [])) {
    if (er.status !== 'COMPLETED' && er.status !== 'FAILED') continue;
    const isNet = er.experiment_type === 'NETWORK_OBSERVATION';
    events.push({
      id: nextId(isNet ? 'net' : 'rt'), phase: isNet ? 'network' : 'runtime',
      title: er.summary || er.experiment_type.replaceAll('_', ' '),
      experimentId: er.experiment_id, status: er.status, evidenceIds: er.evidence_ids,
    });
  }

  // Verification
  if (investigation && investigation.status !== 'disabled') {
    for (const v of (investigation.hypothesis_verifications ?? [])) {
      const isC = v.verified_status === 'CONFIRMED';
      const isCon = v.verified_status === 'CONTRADICTED';
      events.push({
        id: nextId('verify'), phase: 'verification',
        title: isC ? 'Hypothesis Confirmed' : isCon ? 'Hypothesis Contradicted' : `Hypothesis ${v.verified_status}`,
        description: v.deterministic_explanation, hypothesisId: v.hypothesis_id,
        status: v.verified_status, confidence: v.ai_confidence,
        evidenceIds: [...v.static_evidence_ids, ...v.runtime_evidence_ids, ...v.experiment_result_ids],
      });
    }
  }

  // Scoring
  if (result.risk) {
    const adj = result.risk.fraud_delta_adjustment ?? 0;
    const staticScore = Math.max(0, Math.round(result.risk.overall_score - adj));
    const finalScore = result.risk.overall_score;
    events.push({
      id: nextId('score'), phase: 'scoring', title: 'Risk Assessment Complete',
      description: staticScore !== finalScore
        ? `Evidence escalated risk from ${staticScore} to ${finalScore}`
        : `Final risk score: ${finalScore}`,
      scoreFrom: staticScore, scoreTo: finalScore,
      severity: result.risk.severity, confidence: result.risk.confidence,
    });
  }

  events.sort((a, b) => PHASE_ORDER[a.phase] - PHASE_ORDER[b.phase]);
  return events;
}

/* ==================== fixtures ==================== */

const FULL_RESULT = {
  schema_version: '3.0',
  analysis_id: 'test-001',
  decision_notice: 'test',
  malware_assessment: { verdict: 'HIGH_RISK', known_malware: false, legitimacy: 'not-established', explanation: 'test', optional_engine_gaps: 0, safe_to_install: false, limitations: [] },
  engine_analysis: { schema_version: '1.0', orchestrator_version: '1.0', policy: {}, summary: { completed: 1, unavailable_or_failed: 0, normalized_finding_count: 0, tracker_count: 0 }, engines: [], normalized_findings: [], reputation: { verdict: 'unknown', known_malicious: false, providers: [], notice: '' }, coverage_note: '' },
  risk: { overall_score: 91, severity: 'CRITICAL', confidence: 0.85, model_version: '3.0', methodology_note: '', fraud_delta_adjustment: 29, external_engine_evidence_count: 0, sub_scores: { credential_theft: 80, payment_manipulation: 60, fraud_impersonation: 70, evasion_resilience: 50 }, evidence: [] },
  fraud_delta: { score: 29, category: 'banking', baseline_version: '1.0', model_version: '1.0', is_anomalous: true, unexpected_permissions: [], contributions: [] },
  mitre_attack: [],
  emitted_indicators: [],
  runtime_evidence: [
    { evidence_id: 'RT001', timestamp_ms: 1000, evidence_type: 'sms_receiver_activation', source: 'dynamic', process: 'com.test.app', description: 'SMS receiver activated', confidence: 0.9, metadata: {} },
    { evidence_id: 'RT002', timestamp_ms: 2000, evidence_type: 'network_outbound', source: 'dynamic', process: 'com.test.app', description: 'Synthetic OTP marker observed in outbound flow', confidence: 0.88, metadata: {} },
  ],
  experiment_results: [
    { experiment_id: 'EXP-001', experiment_type: 'NETWORK_OBSERVATION', status: 'COMPLETED', started_at_ms: 1000, completed_at_ms: 3000, evidence_ids: ['RT002'], summary: 'Network exfiltration of synthetic marker confirmed', unavailable_reason: null, error: null, metadata: {} },
  ],
  extraction: {
    analysis_mode: 'static', analysis_quality: 'full', engine: 'test', extractor_version: '1.0',
    app: { package_name: 'com.test.fakebank', app_label: 'FakeBank', version_name: '1.0', version_code: '1', min_sdk: '24', target_sdk: '35' },
    permissions: { requested: ['android.permission.READ_SMS', 'android.permission.INTERNET'], flagged_dangerous: ['android.permission.READ_SMS'] },
    components: { activities: [], services: [], receivers: [], providers: [], exported: [], accessibility_service: true, boot_receiver: false, sms_receiver: true },
    code_signals: { sms_api: { detected: true, evidence: ['SmsManager'] }, dynamic_code_loading: { detected: true, evidence: ['DexClassLoader'] } },
    network_indicators: { domains: ['evil.test'], ips: [], urls: [] },
    warnings: [], coverage: {},
  },
  ai_investigation: {
    schema_version: '1.0', provider: 'test', model: 'test-model', status: 'completed',
    hypotheses: [
      {
        hypothesis_id: 'H001', category: 'OTP_INTERCEPTION', status: 'CONFIRMED', confidence: 0.74,
        title: 'Possible OTP interception', reasoning_summary: 'SMS receiver and accessibility service suggest OTP theft',
        supporting_evidence_ids: ['E001', 'E002'], contradicting_evidence_ids: [], missing_evidence: [],
        recommended_experiment_types: ['SYNTHETIC_SMS'], recommended_next_steps: [], limitations: [],
        evidence_strength: 0.8, verification_summary: 'Confirmed via runtime evidence', runtime_evidence_ids: ['RT001'],
      },
    ],
    experiment_plan: [
      {
        experiment_id: 'EXP-001', hypothesis_id: 'H001', experiment_type: 'SYNTHETIC_SMS',
        objective: 'Inject synthetic OTP to observe interception', expected_signal: 'OTP marker in outbound traffic',
        priority: 1, status: 'COMPLETED', description: 'Send synthetic SMS', required_capabilities: [],
        timeout_seconds: 30, safe_by_default: true, produces_evidence_types: [], supported: true, unsupported_reason: null,
      },
    ],
    hypothesis_verifications: [
      {
        hypothesis_id: 'H001', category: 'OTP_INTERCEPTION', original_status: 'PROPOSED', verified_status: 'CONFIRMED',
        evidence_strength: 0.85, ai_confidence: 0.74, static_evidence_ids: ['E001'], runtime_evidence_ids: ['RT001'],
        experiment_result_ids: ['EXP-001'], observed_signals: ['sms_access'], missing_signals: [],
        deterministic_explanation: 'Runtime evidence confirms OTP interception behavior', confirmation_allowed: true,
      },
    ],
    feedback_loop: { rounds_completed: 1, round_limit: 3, max_experiments_per_round: 5, stopped_reason: 'completed' },
    evidence_count: 2,
    evidence: [
      { evidence_id: 'E001', evidence_type: 'permission', source: 'apk-manifest', title: 'READ_SMS', value: 'android.permission.READ_SMS', confidence: 0.95, metadata: {} },
      { evidence_id: 'E002', evidence_type: 'component', source: 'apk-manifest', title: 'Accessibility service', value: 'true', confidence: 0.95, metadata: {} },
    ],
    controls_risk_score: false, can_mark_malicious: false, warning: null, validation_errors: [],
  },
  narrative_metadata: { llm_controls_score: false, source: 'test', warning: null },
};

const MINIMAL_RESULT = {
  schema_version: '3.0', analysis_id: 'test-002', decision_notice: 'test',
  malware_assessment: { verdict: 'INCONCLUSIVE', known_malware: false, legitimacy: 'not-established', explanation: 'test', optional_engine_gaps: 0, safe_to_install: false, limitations: [] },
  engine_analysis: { schema_version: '1.0', orchestrator_version: '1.0', policy: {}, summary: { completed: 1, unavailable_or_failed: 0, normalized_finding_count: 0, tracker_count: 0 }, engines: [], normalized_findings: [], reputation: { verdict: 'unknown', known_malicious: false, providers: [], notice: '' }, coverage_note: '' },
  risk: { overall_score: 35, severity: 'MEDIUM', confidence: 0.6, model_version: '3.0', methodology_note: '', fraud_delta_adjustment: 0, external_engine_evidence_count: 0, sub_scores: { credential_theft: 20, payment_manipulation: 10, fraud_impersonation: 15, evasion_resilience: 10 }, evidence: [] },
  fraud_delta: { score: 0, category: 'utility', baseline_version: '1.0', model_version: '1.0', is_anomalous: false, unexpected_permissions: [], contributions: [] },
  mitre_attack: [], emitted_indicators: [], runtime_evidence: [], experiment_results: [],
  extraction: {
    analysis_mode: 'static', analysis_quality: 'partial', engine: 'test', extractor_version: '1.0',
    app: { package_name: 'com.example.safe' },
    permissions: { requested: ['android.permission.INTERNET'], flagged_dangerous: [] },
    components: { activities: [], services: [], receivers: [], providers: [], exported: [], accessibility_service: false, boot_receiver: false, sms_receiver: false },
    code_signals: {}, network_indicators: { domains: [], ips: [], urls: [] }, warnings: [], coverage: {},
  },
  narrative_metadata: { llm_controls_score: false, source: 'template', warning: null },
};

/* ==================== tests ==================== */

test('buildTimelineEvents returns empty array for null/undefined', () => {
  assert.deepStrictEqual(buildTimelineEvents(null), []);
  assert.deepStrictEqual(buildTimelineEvents(undefined), []);
});

test('full result produces correct event count and phases', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  assert.ok(events.length > 0, 'should produce events');

  const phases = events.map(e => e.phase);
  assert.ok(phases.includes('ingestion'), 'should have ingestion');
  assert.ok(phases.includes('static'), 'should have static');
  assert.ok(phases.includes('ai'), 'should have ai');
  assert.ok(phases.includes('experiment'), 'should have experiment');
  assert.ok(phases.includes('runtime'), 'should have runtime');
  assert.ok(phases.includes('verification'), 'should have verification');
  assert.ok(phases.includes('scoring'), 'should have scoring');
});

test('every event has valid phase and non-empty title', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  for (const event of events) {
    assert.ok(VALID_PHASES.has(event.phase), `invalid phase: ${event.phase}`);
    assert.ok(event.title && event.title.length > 0, `empty title on event ${event.id}`);
  }
});

test('no duplicate event IDs', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const ids = events.map(e => e.id);
  assert.equal(ids.length, new Set(ids).size, 'duplicate IDs detected');
});

test('events are in chronological phase order', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  for (let i = 1; i < events.length; i++) {
    assert.ok(
      PHASE_ORDER[events[i].phase] >= PHASE_ORDER[events[i - 1].phase],
      `phase order violated at index ${i}: ${events[i - 1].phase} -> ${events[i].phase}`
    );
  }
});

test('analysis without ai_investigation still renders ingestion + scoring', () => {
  const events = buildTimelineEvents(MINIMAL_RESULT);
  assert.ok(events.length >= 2, 'should have at least ingestion + scoring');
  assert.equal(events[0].phase, 'ingestion');
  assert.equal(events[events.length - 1].phase, 'scoring');
  assert.ok(!events.some(e => e.phase === 'ai'), 'should not have AI events');
  assert.ok(!events.some(e => e.phase === 'verification'), 'should not have verification events');
});

test('analysis without runtime_evidence produces no runtime events', () => {
  const events = buildTimelineEvents(MINIMAL_RESULT);
  assert.ok(!events.some(e => e.phase === 'runtime'), 'should have no runtime events');
  assert.ok(!events.some(e => e.phase === 'network'), 'should have no network events');
});

test('scoring event includes score transition data', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring, 'scoring event should exist');
  assert.equal(scoring.scoreTo, 91);
  assert.equal(scoring.scoreFrom, 62); // 91 - 29 adjustment
  assert.equal(scoring.severity, 'CRITICAL');
});

test('hypothesis event includes evidence IDs and confidence', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const aiEvent = events.find(e => e.phase === 'ai');
  assert.ok(aiEvent, 'AI hypothesis event should exist');
  assert.ok(aiEvent.evidenceIds?.includes('E001'));
  assert.ok(aiEvent.evidenceIds?.includes('E002'));
  assert.equal(aiEvent.confidence, 0.74);
  assert.equal(aiEvent.hypothesisId, 'H001');
});

test('verification event shows CONFIRMED status', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const verification = events.find(e => e.phase === 'verification');
  assert.ok(verification, 'verification event should exist');
  assert.equal(verification.status, 'CONFIRMED');
  assert.equal(verification.title, 'Hypothesis Confirmed');
});

test('disabled AI investigation produces no AI/experiment/verification events', () => {
  const result = {
    ...FULL_RESULT,
    ai_investigation: { ...FULL_RESULT.ai_investigation, status: 'disabled' },
  };
  const events = buildTimelineEvents(result);
  assert.ok(!events.some(e => e.phase === 'ai'), 'no AI events when disabled');
  assert.ok(!events.some(e => e.phase === 'experiment'), 'no experiment events when disabled');
  assert.ok(!events.some(e => e.phase === 'verification'), 'no verification events when disabled');
});
