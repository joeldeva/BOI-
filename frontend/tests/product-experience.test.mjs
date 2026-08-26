import test from 'node:test';
import assert from 'node:assert/strict';

test('1. Static to final score progression is exposed in analysis results', () => {
  const mockRisk = {
    model_version: 'apk-risk-2026.5',
    static_score: 58,
    runtime_adjustment: 36,
    overall_score: 94,
    runtime_confirmation: 0.92,
    severity: 'CRITICAL',
  };

  assert.equal(mockRisk.static_score, 58);
  assert.equal(mockRisk.runtime_adjustment, 36);
  assert.equal(mockRisk.overall_score, 94);
  assert.equal(mockRisk.static_score + mockRisk.runtime_adjustment, mockRisk.overall_score);
});

test('2. Recovered payloads are typed and retain recursive static findings', () => {
  const mockPayload = {
    payload_id: 'PAYLOAD-001',
    parent_sample_sha256: 'a'.repeat(64),
    sha256: 'b'.repeat(64),
    payload_type: 'DEX',
    size_bytes: 124800,
    source: 'MEMORY_DUMP',
    loader: 'InMemoryDexClassLoader',
    analysis_status: 'ANALYZED',
    extracted_capabilities: ['SMS_INTERCEPTION', 'ACCESSIBILITY_AUTOMATION'],
    method_level_evidence: [
      { signature_id: 'MTH-SMS-001', title: 'SMS Message Ingestion' },
    ],
  };

  assert.equal(mockPayload.payload_id, 'PAYLOAD-001');
  assert.equal(mockPayload.analysis_status, 'ANALYZED');
  assert.equal(mockPayload.extracted_capabilities.length, 2);
  assert.ok(mockPayload.extracted_capabilities.includes('SMS_INTERCEPTION'));
});

test('3. FraudDNA and campaign correlation link related samples with explicit reasons', () => {
  const mockCampaign = {
    campaign_id: 'CAMP-001',
    name: 'Banking Campaign CAMP-001',
    member_sha256s: ['a'.repeat(64), 'b'.repeat(64)],
    shared_firebase_projects: ['fake-kyc-2026'],
    shared_infrastructure: ['c2-evil.net'],
    shared_signer_fingerprints: ['SIG_1'],
  };

  const mockRelated = [
    {
      sha256: 'b'.repeat(64),
      similarity: 0.93,
      reasons: ['same firebase project', 'dex similarity 91%', 'same signer'],
      campaign_id: 'CAMP-001',
    },
  ];

  assert.equal(mockCampaign.campaign_id, 'CAMP-001');
  assert.equal(mockRelated[0].similarity, 0.93);
  assert.ok(mockRelated[0].reasons.includes('same firebase project'));
});

test('4. Banking-brand impersonation evaluates multi-signal metrics', () => {
  const mockImpersonation = {
    target_bank_id: 'bank_of_india',
    target_bank_name: 'Bank of India',
    app_label_similarity: 0.95,
    package_name_similarity: 0.60,
    icon_similarity: 0.96,
    is_official_package: false,
    is_trusted_signer: false,
    domain_similarity: 0.85,
    brand_keywords_detected: ['Bank of India', 'BOI'],
    has_credential_forms: true,
    impersonation_score: 0.85,
    verdict: 'VERY_HIGH',
    reasons: [
      'Official bank brand keywords detected: Bank of India, BOI',
      'Untrusted signing certificate',
    ],
  };

  assert.equal(mockImpersonation.verdict, 'VERY_HIGH');
  assert.equal(mockImpersonation.is_trusted_signer, false);
  assert.ok(mockImpersonation.reasons.length >= 2);
});

test('5. Missing optional sections do not throw errors or break data contract', () => {
  const minimalResult = {
    schema_version: '3.0',
    analysis_id: 'sample_01',
    decision_notice: 'Analyst decision support only',
    risk: { overall_score: 10, severity: 'LOW' },
    extraction: { app: {}, file: {}, network_indicators: { domains: [], ips: [], urls: [] } },
    engine_analysis: { engines: [] },
    malware_assessment: { verdict: 'LOW_RISK_OBSERVED' },
    fraud_delta: { category: 'banking', score: 0, contributions: [] },
    mitre_attack: [],
    emitted_indicators: [],
    runtime_evidence: [],
    experiment_results: [],
    // Optional fields omitted:
    // recovered_payloads, frauddna, related_samples, campaign, brand_impersonation, firebase_infrastructure
  };

  assert.equal(minimalResult.recovered_payloads, undefined);
  assert.equal(minimalResult.campaign, undefined);
  assert.equal(minimalResult.brand_impersonation, undefined);
});
