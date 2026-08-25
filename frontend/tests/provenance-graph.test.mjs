import test from 'node:test';
import assert from 'node:assert/strict';

/* =========================================================================
   Standalone JS Implementation of Provenance Graph Builder for Testing
   ========================================================================= */

function buildProvenanceGraph(result) {
  if (!result) {
    return {
      nodes: [],
      edges: [],
      summary: { totalNodes: 0, totalEdges: 0, impactCount: 0, confirmedCount: 0, staticCount: 0 },
      impactNodes: [],
    };
  }

  const nodes = [];
  const edges = [];
  const nodeMap = new Map();
  const edgeSet = new Set();

  function addNode(node) {
    if (!nodeMap.has(node.id)) {
      nodeMap.set(node.id, node);
      nodes.push(node);
    }
  }

  function addEdge(sourceId, targetId, type, label, animated = false) {
    if (!nodeMap.has(sourceId) || !nodeMap.has(targetId)) return;
    const key = `${sourceId}->${targetId}:${type}`;
    if (!edgeSet.has(key)) {
      edgeSet.add(key);
      const sourceNode = nodeMap.get(sourceId);
      const targetNode = nodeMap.get(targetId);
      const isConfirmed = sourceNode.state === 'RUNTIME_CONFIRMED' || targetNode.state === 'RUNTIME_CONFIRMED';
      edges.push({
        id: `e-${edges.length + 1}`,
        source: sourceId,
        target: targetId,
        type,
        label: label || type.toLowerCase().replaceAll('_', ' '),
        animated: animated || isConfirmed,
        state: isConfirmed ? 'RUNTIME_CONFIRMED' : targetNode.state,
      });
    }
  }

  const extraction = result.extraction || {};
  const permissions = extraction.permissions || { requested: [], flagged_dangerous: [] };
  const components = extraction.components || {};
  const codeSignals = extraction.code_signals || {};
  const network = extraction.network_indicators || { domains: [], ips: [], urls: [] };
  const runtimeEvidence = result.runtime_evidence || [];
  const experimentResults = result.experiment_results || [];
  const aiInvestigation = result.ai_investigation;
  const verifications = aiInvestigation?.hypothesis_verifications || [];
  const hypotheses = aiInvestigation?.hypotheses || [];

  const hasRuntimeConfirmed = (pattern) =>
    runtimeEvidence.some(
      (re) =>
        re.evidence_type.toLowerCase().includes(pattern.toLowerCase()) ||
        re.description.toLowerCase().includes(pattern.toLowerCase())
    ) ||
    experimentResults.some(
      (er) =>
        er.status === 'COMPLETED' &&
        (er.summary?.toLowerCase().includes(pattern.toLowerCase()) ||
          er.experiment_type.toLowerCase().includes(pattern.toLowerCase()))
    );

  const isHypothesisConfirmed = (category) =>
    verifications.some(
      (v) =>
        v.category.toUpperCase().includes(category.toUpperCase()) &&
        v.verified_status === 'CONFIRMED'
    ) ||
    hypotheses.some(
      (h) =>
        h.category.toUpperCase().includes(category.toUpperCase()) &&
        h.status === 'CONFIRMED'
    );

  // LAYER 0
  const requested = permissions.requested || [];
  const dangerous = permissions.flagged_dangerous || [];

  if (requested.includes('android.permission.READ_SMS') || dangerous.includes('android.permission.READ_SMS')) {
    addNode({
      id: 'perm_read_sms',
      type: 'PERMISSION',
      label: 'READ_SMS',
      state: 'STATIC',
      layer: 0,
      evidenceId: 'E-PERM-SMS',
    });
  }

  if (requested.includes('android.permission.RECEIVE_SMS') || dangerous.includes('android.permission.RECEIVE_SMS')) {
    addNode({
      id: 'perm_recv_sms',
      type: 'PERMISSION',
      label: 'RECEIVE_SMS',
      state: 'STATIC',
      layer: 0,
      evidenceId: 'E-PERM-RECVSMS',
    });
  }

  if (requested.includes('android.permission.SYSTEM_ALERT_WINDOW') || dangerous.includes('android.permission.SYSTEM_ALERT_WINDOW')) {
    addNode({
      id: 'perm_alert_window',
      type: 'PERMISSION',
      label: 'SYSTEM_ALERT_WINDOW',
      state: 'STATIC',
      layer: 0,
      evidenceId: 'E-PERM-OVERLAY',
    });
  }

  if (requested.includes('android.permission.INTERNET') || network.domains?.length > 0) {
    addNode({
      id: 'perm_internet',
      type: 'PERMISSION',
      label: 'INTERNET',
      state: 'STATIC',
      layer: 0,
      evidenceId: 'E-PERM-NET',
    });
  }

  // LAYER 1
  if (components.sms_receiver) {
    addNode({
      id: 'comp_sms_receiver',
      type: 'COMPONENT',
      label: 'SmsReceiver',
      state: 'STATIC',
      layer: 1,
      evidenceId: 'E-COMP-SMS',
    });
    if (nodeMap.has('perm_read_sms')) addEdge('perm_read_sms', 'comp_sms_receiver', 'DECLARES');
    if (nodeMap.has('perm_recv_sms')) addEdge('perm_recv_sms', 'comp_sms_receiver', 'DECLARES');
  }

  if (components.accessibility_service) {
    addNode({
      id: 'comp_accessibility',
      type: 'COMPONENT',
      label: 'AccessibilityService',
      state: 'STATIC',
      layer: 1,
      evidenceId: 'E-COMP-A11Y',
    });
    if (nodeMap.has('perm_alert_window')) addEdge('perm_alert_window', 'comp_accessibility', 'DECLARES');
  }

  if (codeSignals.sms_api?.detected) {
    addNode({
      id: 'api_sms_manager',
      type: 'API',
      label: 'SmsManager API',
      state: 'STATIC',
      layer: 1,
      evidenceId: 'E-API-SMS',
    });
    if (nodeMap.has('comp_sms_receiver')) addEdge('comp_sms_receiver', 'api_sms_manager', 'INVOKES');
  }

  if (codeSignals.input_injection?.detected) {
    addNode({
      id: 'api_dispatch_gesture',
      type: 'API',
      label: 'dispatchGesture()',
      state: 'STATIC',
      layer: 1,
      evidenceId: 'E-API-GESTURE',
    });
    if (nodeMap.has('comp_accessibility')) addEdge('comp_accessibility', 'api_dispatch_gesture', 'INVOKES');
  }

  // LAYER 2
  const otpObserved = hasRuntimeConfirmed('otp') || hasRuntimeConfirmed('sms');
  const otpState = otpObserved ? 'RUNTIME_CONFIRMED' : 'INFERRED';

  if (nodeMap.has('comp_sms_receiver') || nodeMap.has('perm_read_sms')) {
    addNode({
      id: 'data_otp_token',
      type: 'DATA',
      label: 'Incoming SMS / OTP Token',
      state: otpState,
      layer: 2,
      evidenceId: 'E-DATA-OTP',
    });
    if (nodeMap.has('comp_sms_receiver')) addEdge('comp_sms_receiver', 'data_otp_token', 'READS');
  }

  if (nodeMap.has('comp_accessibility')) {
    addNode({
      id: 'data_screen_buffer',
      type: 'DATA',
      label: 'On-Screen Credentials & PIN',
      state: 'INFERRED',
      layer: 2,
      evidenceId: 'E-DATA-SCREEN',
    });
    addEdge('comp_accessibility', 'data_screen_buffer', 'READS');
  }

  if (otpObserved || runtimeEvidence.length > 0) {
    addNode({
      id: 'runtime_otp_access',
      type: 'RUNTIME_EVENT',
      label: 'Synthetic OTP Marker Intercepted',
      state: 'RUNTIME_CONFIRMED',
      layer: 2,
      evidenceId: 'RT-001',
    });
    if (nodeMap.has('data_otp_token')) addEdge('data_otp_token', 'runtime_otp_access', 'OBSERVED_AFTER', 'observed in sandbox', true);
  }

  // LAYER 3
  const c2Domain = network.domains?.[0] || network.ips?.[0] || network.urls?.[0];
  const netExfilObserved = hasRuntimeConfirmed('network') || hasRuntimeConfirmed('outbound') || hasRuntimeConfirmed('marker');
  const netState = netExfilObserved ? 'RUNTIME_CONFIRMED' : 'STATIC';

  if (c2Domain) {
    addNode({
      id: 'net_c2_endpoint',
      type: 'NETWORK',
      label: `C2: ${c2Domain}`,
      state: netState,
      layer: 3,
      evidenceId: 'E-NET-C2',
    });
    if (nodeMap.has('perm_internet')) addEdge('perm_internet', 'net_c2_endpoint', 'ENABLES');
    if (nodeMap.has('runtime_otp_access')) addEdge('runtime_otp_access', 'net_c2_endpoint', 'SENDS_TO', 'outbound HTTP POST', true);
  }

  const isOtpConfirmed = isHypothesisConfirmed('OTP') || (nodeMap.has('comp_sms_receiver') && otpObserved);
  const otpBehaviorState = isOtpConfirmed ? 'RUNTIME_CONFIRMED' : 'INFERRED';

  if (nodeMap.has('comp_sms_receiver') || nodeMap.has('data_otp_token')) {
    addNode({
      id: 'behavior_otp_interception',
      type: 'BEHAVIOR',
      label: 'OTP Interception & Exfiltration',
      state: otpBehaviorState,
      layer: 3,
      evidenceId: 'H-OTP-EXFIL',
    });
    if (nodeMap.has('net_c2_endpoint')) addEdge('net_c2_endpoint', 'behavior_otp_interception', 'SUPPORTS');
  }

  // LAYER 4
  if (nodeMap.has('behavior_otp_interception') || nodeMap.has('data_otp_token')) {
    addNode({
      id: 'impact_otp_theft',
      type: 'BANKING_IMPACT',
      label: 'OTP Theft',
      state: 'IMPACT',
      layer: 4,
      evidenceId: 'IMPACT-OTP',
    });
    if (nodeMap.has('behavior_otp_interception')) addEdge('behavior_otp_interception', 'impact_otp_theft', 'ENABLES');

    addNode({
      id: 'impact_account_takeover',
      type: 'BANKING_IMPACT',
      label: 'Account Takeover (ATO)',
      state: 'IMPACT',
      layer: 4,
      evidenceId: 'IMPACT-ATO',
    });
    addEdge('impact_otp_theft', 'impact_account_takeover', 'ENABLES');
  }

  if (nodeMap.has('comp_accessibility')) {
    addNode({
      id: 'impact_cred_theft',
      type: 'BANKING_IMPACT',
      label: 'Credential Theft',
      state: 'IMPACT',
      layer: 4,
      evidenceId: 'IMPACT-CRED',
    });
    addNode({
      id: 'impact_unauth_tx',
      type: 'BANKING_IMPACT',
      label: 'Unauthorized Transaction Risk',
      state: 'IMPACT',
      layer: 4,
      evidenceId: 'IMPACT-TX',
    });
    addEdge('impact_cred_theft', 'impact_unauth_tx', 'ENABLES');
  }

  const impactNodes = nodes.filter((n) => n.type === 'BANKING_IMPACT');
  const confirmedCount = nodes.filter((n) => n.state === 'RUNTIME_CONFIRMED').length;
  const staticCount = nodes.filter((n) => n.state === 'STATIC').length;

  return {
    nodes,
    edges,
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      impactCount: impactNodes.length,
      confirmedCount,
      staticCount,
    },
    impactNodes,
  };
}

/* =========================================================================
   Mock Fixture Data
   ========================================================================= */

const HERO_APK_RESULT = {
  schema_version: '3.0',
  analysis_id: 'apk-test-hero',
  decision_notice: 'test',
  malware_assessment: { verdict: 'HIGH_RISK', known_malware: false, legitimacy: 'not-established', explanation: 'Hero banking malware fixture', optional_engine_gaps: 0, safe_to_install: false, limitations: [] },
  engine_analysis: { schema_version: '1.0', orchestrator_version: '1.0', policy: {}, summary: { completed: 2, unavailable_or_failed: 0, normalized_finding_count: 3, tracker_count: 0 }, engines: [], normalized_findings: [], reputation: { verdict: 'malicious', known_malicious: true, providers: [], notice: '' }, coverage_note: '' },
  risk: { overall_score: 94, severity: 'CRITICAL', confidence: 0.95, model_version: '3.0', methodology_note: '', fraud_delta_adjustment: 32, external_engine_evidence_count: 2, sub_scores: { credential_theft: 88, payment_manipulation: 75, fraud_impersonation: 80, evasion_resilience: 60 }, evidence: [] },
  fraud_delta: { score: 32, category: 'banking', baseline_version: '1.0', model_version: '1.0', is_anomalous: true, unexpected_permissions: [], contributions: [] },
  mitre_attack: [],
  emitted_indicators: [],
  runtime_evidence: [
    { evidence_id: 'RT001', timestamp_ms: 1000, evidence_type: 'sms_receiver_activation', source: 'dynamic', process: 'com.demo.bank', description: 'SMS receiver activated for synthetic SMS', confidence: 0.98, metadata: {} },
    { evidence_id: 'RT002', timestamp_ms: 2000, evidence_type: 'synthetic_marker_correlation', source: 'dynamic', process: 'com.demo.bank', description: 'Synthetic OTP marker observed in outbound flow', confidence: 0.95, metadata: {} },
  ],
  experiment_results: [
    { experiment_id: 'EXP-001', experiment_type: 'SYNTHETIC_SMS', status: 'COMPLETED', started_at_ms: 1000, completed_at_ms: 2500, evidence_ids: ['RT001'], summary: 'Synthetic OTP injected and captured by receiver', unavailable_reason: null, error: null, metadata: {} },
    { experiment_id: 'EXP-002', experiment_type: 'NETWORK_OBSERVATION', status: 'COMPLETED', started_at_ms: 2600, completed_at_ms: 4000, evidence_ids: ['RT002'], summary: 'Network exfiltration of synthetic marker confirmed', unavailable_reason: null, error: null, metadata: {} },
  ],
  extraction: {
    analysis_mode: 'static', analysis_quality: 'full', engine: 'test', extractor_version: '1.0',
    app: { package_name: 'com.fraudshield.demo.fakebank', app_label: 'BOI Rewards Secure' },
    permissions: {
      requested: [
        'android.permission.INTERNET',
        'android.permission.READ_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.SYSTEM_ALERT_WINDOW',
      ],
      flagged_dangerous: [
        'android.permission.READ_SMS',
        'android.permission.RECEIVE_SMS',
        'android.permission.SYSTEM_ALERT_WINDOW',
      ],
    },
    components: {
      activities: ['MainActivity'],
      services: ['CaptureService'],
      receivers: ['SmsReceiver'],
      providers: [],
      exported: [],
      sms_receiver: true,
      boot_receiver: true,
      accessibility_service: true,
    },
    code_signals: {
      sms_api: { detected: true, evidence: ['SmsManager'] },
      input_injection: { detected: true, evidence: ['dispatchGesture'] },
    },
    network_indicators: {
      domains: ['c2-demo.fraudshield.invalid'],
      ips: ['198.51.100.42'],
      urls: ['https://c2-demo.fraudshield.invalid/gate'],
    },
    warnings: [], coverage: {},
  },
  ai_investigation: {
    schema_version: '1.0', provider: 'test', model: 'test-model', status: 'completed',
    hypotheses: [
      {
        hypothesis_id: 'H001', category: 'OTP_INTERCEPTION', status: 'CONFIRMED', confidence: 0.94,
        title: 'OTP Interception and Exfiltration', reasoning_summary: 'SMS receiver and accessibility service suggest OTP theft',
        supporting_evidence_ids: ['E001', 'E002'], contradicting_evidence_ids: [], missing_evidence: [],
        recommended_experiment_types: ['SYNTHETIC_SMS'], recommended_next_steps: [], limitations: [],
        evidence_strength: 0.95, verification_summary: 'Confirmed via runtime marker correlation', runtime_evidence_ids: ['RT001', 'RT002'],
      },
    ],
    experiment_plan: [],
    hypothesis_verifications: [
      {
        hypothesis_id: 'H001', category: 'OTP_INTERCEPTION', original_status: 'PROPOSED', verified_status: 'CONFIRMED',
        evidence_strength: 0.95, ai_confidence: 0.94, static_evidence_ids: ['E001'], runtime_evidence_ids: ['RT001', 'RT002'],
        experiment_result_ids: ['EXP-001', 'EXP-002'], observed_signals: ['sms_access', 'marker_exfil'], missing_signals: [],
        deterministic_explanation: 'Runtime evidence confirms OTP interception and exfiltration', confirmation_allowed: true,
      },
    ],
    feedback_loop: {}, evidence_count: 2, evidence: [], controls_risk_score: false, can_mark_malicious: false, warning: null, validation_errors: [],
  },
  narrative_metadata: { llm_controls_score: false, source: 'test', warning: null },
};

/* =========================================================================
   Unit Tests
   ========================================================================= */

test('buildProvenanceGraph handles null and undefined gracefully', () => {
  const emptyNull = buildProvenanceGraph(null);
  assert.equal(emptyNull.nodes.length, 0);
  assert.equal(emptyNull.edges.length, 0);
  assert.equal(emptyNull.summary.totalNodes, 0);

  const emptyUndef = buildProvenanceGraph(undefined);
  assert.equal(emptyUndef.nodes.length, 0);
  assert.equal(emptyUndef.edges.length, 0);
});

test('buildProvenanceGraph builds full multi-layer graph for Hero APK', () => {
  const graph = buildProvenanceGraph(HERO_APK_RESULT);
  assert.ok(graph.nodes.length >= 8, `Expected at least 8 nodes, got ${graph.nodes.length}`);
  assert.ok(graph.edges.length >= 6, `Expected at least 6 edges, got ${graph.edges.length}`);
  assert.ok(graph.summary.impactCount >= 2, `Expected at least 2 banking impact nodes, got ${graph.summary.impactCount}`);
});

test('all required node types are present in complete analysis', () => {
  const graph = buildProvenanceGraph(HERO_APK_RESULT);
  const types = new Set(graph.nodes.map((n) => n.type));

  assert.ok(types.has('PERMISSION'), 'Should contain PERMISSION nodes');
  assert.ok(types.has('COMPONENT'), 'Should contain COMPONENT nodes');
  assert.ok(types.has('API'), 'Should contain API nodes');
  assert.ok(types.has('DATA'), 'Should contain DATA nodes');
  assert.ok(types.has('RUNTIME_EVENT'), 'Should contain RUNTIME_EVENT nodes');
  assert.ok(types.has('NETWORK'), 'Should contain NETWORK nodes');
  assert.ok(types.has('BEHAVIOR'), 'Should contain BEHAVIOR nodes');
  assert.ok(types.has('BANKING_IMPACT'), 'Should contain BANKING_IMPACT nodes');
});

test('all required edge types connect valid nodes without dangling references', () => {
  const graph = buildProvenanceGraph(HERO_APK_RESULT);
  const nodeIds = new Set(graph.nodes.map((n) => n.id));

  for (const edge of graph.edges) {
    assert.ok(nodeIds.has(edge.source), `Dangling edge source: ${edge.source}`);
    assert.ok(nodeIds.has(edge.target), `Dangling edge target: ${edge.target}`);
    assert.ok(edge.type, `Edge ${edge.id} must have a valid type`);
  }
});

test('provenance graph shows confirmed runtime states when verified in sandbox', () => {
  const graph = buildProvenanceGraph(HERO_APK_RESULT);
  const confirmedNodes = graph.nodes.filter((n) => n.state === 'RUNTIME_CONFIRMED');
  assert.ok(confirmedNodes.length >= 2, 'Should have multiple runtime confirmed nodes');

  const otpBehavior = graph.nodes.find((n) => n.id === 'behavior_otp_interception');
  assert.ok(otpBehavior, 'OTP interception behavior node should exist');
  assert.equal(otpBehavior.state, 'RUNTIME_CONFIRMED');
});

test('deterministic banking impact includes Account Takeover and OTP Theft', () => {
  const graph = buildProvenanceGraph(HERO_APK_RESULT);
  const impactLabels = graph.impactNodes.map((n) => n.label);

  assert.ok(impactLabels.includes('OTP Theft'), 'Must include OTP Theft impact');
  assert.ok(impactLabels.includes('Account Takeover (ATO)'), 'Must include Account Takeover impact');

  const atoEdge = graph.edges.find((e) => e.source === 'impact_otp_theft' && e.target === 'impact_account_takeover');
  assert.ok(atoEdge, 'OTP Theft must connect to Account Takeover via ENABLES edge');
  assert.equal(atoEdge.type, 'ENABLES');
});

test('minimal static APK produces clean DAG without fake runtime events', () => {
  const minimalStatic = {
    extraction: {
      permissions: { requested: ['android.permission.INTERNET'], flagged_dangerous: [] },
      components: {},
      code_signals: {},
      network_indicators: { domains: [], ips: [], urls: [] },
    },
    runtime_evidence: [],
    experiment_results: [],
  };

  const graph = buildProvenanceGraph(minimalStatic);
  assert.ok(graph.nodes.length >= 1, 'Should have at least 1 node (INTERNET perm)');
  const runtimeNodes = graph.nodes.filter((n) => n.type === 'RUNTIME_EVENT');
  assert.equal(runtimeNodes.length, 0, 'No fake runtime event nodes should exist');
});
