import test from 'node:test';
import assert from 'node:assert/strict';

/**
 * Pure function mirror of timeline builder logic for node --test execution.
 */

const PHASE_ORDER = {
  ingestion: 0,
  static: 1,
  engine: 2,
  ai: 3,
  experiment: 4,
  runtime: 5,
  network: 6,
  verification: 7,
  scoring: 8,
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

  // Engine
  const engineAnalysis = result.engine_analysis;
  if (engineAnalysis) {
    const completedEngines = (engineAnalysis.engines || []).filter(e => e.status === 'completed');
    if (completedEngines.length > 0) {
      events.push({
        id: nextId('engine'), phase: 'engine', title: 'Static & Heuristic Engines',
        description: `${completedEngines.length} engine(s) evaluated`,
        details: completedEngines.map(e => `${e.engine_name}: completed`),
      });
    }
    const normalizedFindings = engineAnalysis.normalized_findings || [];
    if (normalizedFindings.length > 0) {
      events.push({
        id: nextId('engine'), phase: 'engine', title: 'Normalized Engine Findings',
        description: `${normalizedFindings.length} findings`,
        details: normalizedFindings.slice(0, 5).map(f => `${f.category}: ${f.title}`),
      });
    }
  }

  // AI & Experiments
  const investigation = result.ai_investigation;
  if (investigation && investigation.status !== 'disabled') {
    for (const h of investigation.hypotheses) {
      events.push({
        id: nextId('ai'), phase: 'ai', title: h.title, description: h.reasoning_summary,
        hypothesisId: h.hypothesis_id, confidence: h.confidence, status: h.status,
        evidenceIds: h.supporting_evidence_ids, isAiGenerated: true,
      });
    }
    for (const exp of investigation.experiment_plan) {
      events.push({
        id: nextId('exp'), phase: 'experiment',
        title: `Experiment Requested: ${exp.experiment_type.replaceAll('_', ' ')}`,
        description: exp.objective, experimentId: exp.experiment_id,
        hypothesisId: exp.hypothesis_id, status: exp.status, isAiGenerated: true,
      });
    }
  }

  // Runtime
  for (const ev of (result.runtime_evidence ?? [])) {
    const isNet = ev.evidence_type.toLowerCase().includes('network') ||
                  ev.evidence_type.toLowerCase().includes('outbound') ||
                  ev.evidence_type.toLowerCase().includes('dns');
    events.push({
      id: nextId(isNet ? 'net' : 'rt'), phase: isNet ? 'network' : 'runtime',
      title: ev.description || ev.evidence_type,
      description: ev.process ? `Process: ${ev.process}` : undefined,
      confidence: ev.confidence, trustLevel: ev.trust_level, status: ev.trust_level || ev.source,
      evidenceIds: [ev.evidence_id],
    });
  }
  for (const er of (result.experiment_results ?? [])) {
    if (er.status !== 'COMPLETED' && er.status !== 'FAILED') continue;
    const isNet = er.experiment_type === 'NETWORK_OBSERVATION';
    events.push({
      id: nextId(isNet ? 'net' : 'rt'), phase: isNet ? 'network' : 'runtime',
      title: `Experiment Executed: ${er.summary || er.experiment_type.replaceAll('_', ' ')}`,
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
        status: v.verified_status, confidence: v.ai_confidence, evidenceStrength: v.evidence_strength,
        evidenceIds: [...v.static_evidence_ids, ...v.runtime_evidence_ids, ...v.experiment_result_ids],
      });
    }
  }

  // Scoring
  if (result.risk) {
    const staticScore = typeof result.risk.static_score === 'number'
      ? result.risk.static_score
      : Math.max(0, Math.round(result.risk.overall_score - (result.risk.fraud_delta_adjustment ?? 0)));
    const runtimeAdjustment = typeof result.risk.runtime_adjustment === 'number'
      ? result.risk.runtime_adjustment
      : (result.risk.fraud_delta_adjustment ?? 0);
    const finalScore = result.risk.overall_score;
    const hasEscalation = runtimeAdjustment > 0 && staticScore !== finalScore;
    const runtimeRuleIds = (result.risk.runtime_rules || []).map(r => r.rule_id || r.rule_name).filter(Boolean);

    events.push({
      id: nextId('score'), phase: 'scoring',
      title: hasEscalation ? 'Deterministic Risk Escalation' : 'Risk Assessment Complete',
      description: hasEscalation
        ? `Verified runtime behavior confirmed (+${runtimeAdjustment} pts), escalating risk from ${staticScore} to ${finalScore}`
        : `Final deterministic fraud risk: ${finalScore}`,
      scoreFrom: staticScore, scoreTo: finalScore, runtimeAdjustment,
      severity: result.risk.severity, confidence: result.risk.confidence,
      scoringRules: runtimeRuleIds,
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
  engine_analysis: { schema_version: '1.0', orchestrator_version: '1.0', policy: {}, summary: { completed: 1, unavailable_or_failed: 0, normalized_finding_count: 0, tracker_count: 0 }, engines: [{ engine_name: 'dex_analyzer', status: 'completed' }], normalized_findings: [{ category: 'SMS', title: 'SMS Access' }], reputation: { verdict: 'unknown', known_malicious: false, providers: [], notice: '' }, coverage_note: '' },
  risk: {
    model_version: 'apk-risk-2026.5',
    static_score: 62,
    runtime_adjustment: 29,
    overall_score: 91,
    severity: 'CRITICAL',
    confidence: 0.85,
    runtime_confirmation: 0.95,
    static_rules: [{ rule_id: 'APK-CRED-001', rule_name: 'Read SMS', points: 18 }],
    runtime_rules: [{ rule_id: 'RUNTIME-OTP-001', rule_name: 'Confirmed synthetic SMS', points: 20 }],
    sub_scores: { credential_theft: 80, payment_manipulation: 60, fraud_impersonation: 70, evasion_resilience: 50 },
    evidence: [],
  },
  mitre_attack: [],
  emitted_indicators: [],
  runtime_evidence: [
    { evidence_id: 'RT001', timestamp_ms: 1000, evidence_type: 'sms_receiver_activation', trust_level: 'INSTRUMENTED', source: 'dynamic', process: 'com.test.app', description: 'SMS receiver activated', confidence: 0.9, metadata: {} },
    { evidence_id: 'RT002', timestamp_ms: 2000, evidence_type: 'network_outbound', trust_level: 'PAYLOAD_CORRELATED', source: 'dynamic', process: 'com.test.app', description: 'Synthetic OTP marker observed in outbound flow', confidence: 0.88, metadata: {} },
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
  risk: { static_score: 35, runtime_adjustment: 0, overall_score: 35, severity: 'MEDIUM', confidence: 0.6, model_version: 'apk-risk-2026.5', static_rules: [], runtime_rules: [], sub_scores: { credential_theft: 20, payment_manipulation: 10, fraud_impersonation: 15, evasion_resilience: 10 }, evidence: [] },
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

// 1. static_score shown from backend
test('1. static_score shown from backend', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring);
  assert.equal(scoring.scoreFrom, 62, 'static_score should equal 62 from backend');
});

// 2. runtime_adjustment shown correctly
test('2. runtime_adjustment shown correctly', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring);
  assert.equal(scoring.runtimeAdjustment, 29, 'runtime_adjustment should equal 29 from backend');
});

// 3. overall_score shown correctly
test('3. overall_score shown correctly', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring);
  assert.equal(scoring.scoreTo, 91, 'scoreTo should equal 91 from backend');
});

// 4. no fake escalation when adjustment is zero
test('4. no fake escalation when adjustment is zero', () => {
  const events = buildTimelineEvents(MINIMAL_RESULT);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring);
  assert.equal(scoring.runtimeAdjustment, 0);
  assert.equal(scoring.scoreFrom, 35);
  assert.equal(scoring.scoreTo, 35);
  assert.equal(scoring.title, 'Risk Assessment Complete');
  assert.ok(!scoring.description.includes('escalated'));
});

// 5. CONFIRMED/SUPPORTED/INCONCLUSIVE render distinctly
test('5. CONFIRMED/SUPPORTED/INCONCLUSIVE render distinctly', () => {
  const customResult = {
    ...FULL_RESULT,
    ai_investigation: {
      ...FULL_RESULT.ai_investigation,
      hypothesis_verifications: [
        { hypothesis_id: 'H001', category: 'OTP', verified_status: 'CONFIRMED', evidence_strength: 0.95, ai_confidence: 0.8, static_evidence_ids: [], runtime_evidence_ids: [], experiment_result_ids: [], deterministic_explanation: 'Confirmed' },
        { hypothesis_id: 'H002', category: 'ACC', verified_status: 'SUPPORTED', evidence_strength: 0.60, ai_confidence: 0.7, static_evidence_ids: [], runtime_evidence_ids: [], experiment_result_ids: [], deterministic_explanation: 'Supported only' },
        { hypothesis_id: 'H003', category: 'NET', verified_status: 'INCONCLUSIVE', evidence_strength: 0.20, ai_confidence: 0.5, static_evidence_ids: [], runtime_evidence_ids: [], experiment_result_ids: [], deterministic_explanation: 'Inconclusive' },
      ],
    },
  };
  const events = buildTimelineEvents(customResult);
  const verifications = events.filter(e => e.phase === 'verification');
  assert.equal(verifications.length, 3);
  assert.equal(verifications[0].status, 'CONFIRMED');
  assert.equal(verifications[0].title, 'Hypothesis Confirmed');
  assert.equal(verifications[1].status, 'SUPPORTED');
  assert.equal(verifications[1].title, 'Hypothesis SUPPORTED');
  assert.equal(verifications[2].status, 'INCONCLUSIVE');
  assert.equal(verifications[2].title, 'Hypothesis INCONCLUSIVE');
});

// 6. experiment -> evidence relationships
test('6. experiment -> evidence relationships are preserved', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  const executedExp = events.find(e => (e.phase === 'runtime' || e.phase === 'network') && e.experimentId === 'EXP-001');
  assert.ok(executedExp);
  assert.deepStrictEqual(executedExp.evidenceIds, ['RT002']);

  const verificationEvent = events.find(e => e.phase === 'verification');
  assert.ok(verificationEvent);
  assert.ok(verificationEvent.evidenceIds.includes('RT001'));
  assert.ok(verificationEvent.evidenceIds.includes('EXP-001'));
});

// 7. timeline phase ordering
test('7. timeline phase ordering follows strict chronological lifecycle', () => {
  const events = buildTimelineEvents(FULL_RESULT);
  assert.ok(events.length >= 7);
  for (let i = 0; i < events.length; i++) {
    assert.ok(VALID_PHASES.has(events[i].phase), `Invalid phase: ${events[i].phase}`);
  }
  for (let i = 1; i < events.length; i++) {
    assert.ok(
      PHASE_ORDER[events[i].phase] >= PHASE_ORDER[events[i - 1].phase],
      `Phase order violated at index ${i}: ${events[i - 1].phase} -> ${events[i].phase}`
    );
  }
});

// 8. missing optional AI investigation does not crash UI
test('8. missing optional AI investigation does not crash UI', () => {
  const events = buildTimelineEvents(MINIMAL_RESULT);
  assert.ok(events.length >= 2);
  assert.equal(events[0].phase, 'ingestion');
  assert.equal(events[events.length - 1].phase, 'scoring');
  assert.ok(!events.some(e => e.phase === 'ai'));
  assert.ok(!events.some(e => e.phase === 'verification'));
});

// 9. old stored analysis response remains reasonably compatible where practical
test('9. old stored analysis response remains reasonably compatible where practical', () => {
  const legacyResult = {
    schema_version: '2.0',
    risk: {
      overall_score: 85,
      fraud_delta_adjustment: 20,
      severity: 'HIGH',
      confidence: 0.8,
    },
    extraction: {
      app: { package_name: 'com.legacy.app' },
    },
  };
  const events = buildTimelineEvents(legacyResult);
  const scoring = events.find(e => e.phase === 'scoring');
  assert.ok(scoring);
  assert.equal(scoring.scoreFrom, 65, 'fallback should compute 85 - 20 = 65');
  assert.equal(scoring.scoreTo, 85);
  assert.equal(scoring.runtimeAdjustment, 20);
});
