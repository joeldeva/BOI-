import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';

import {
  aggregateExperimentStatus,
  isRuntimeNetworkEvidence,
  isRuntimeReady,
  knownMaliciousLabel,
  severityFromScore,
} from '../src/utils/analysisTruth.mjs';

test('runtime readiness uses the canonical backend field', () => {
  const capabilities = {
    dynamic_lite: {
      runtime_ready: false,
      enabled: true,
      adb_available: true,
      emulator_configured: true,
    },
  };
  assert.equal(isRuntimeReady(capabilities), false);
  capabilities.dynamic_lite.runtime_ready = true;
  assert.equal(isRuntimeReady(capabilities), true);
});

test('not-queried and unsuccessful reputation display NOT EVALUATED', () => {
  assert.equal(knownMaliciousLabel({ verdict: 'not-queried', known_malicious: false, providers: [] }), 'NOT EVALUATED');
  assert.equal(knownMaliciousLabel({ verdict: 'unavailable', known_malicious: false, providers: [] }), 'NOT EVALUATED');
  assert.equal(knownMaliciousLabel({ verdict: 'not-found', known_malicious: false, providers: [{ id: 'malwarebazaar' }] }), 'No');
});

test('experiment aggregate reports partial and exact counts', () => {
  const aggregate = aggregateExperimentStatus([
    { status: 'COMPLETED' },
    { status: 'FAILED' },
    { status: 'TIMED_OUT' },
  ]);
  assert.equal(aggregate.status, 'PARTIAL');
  assert.deepEqual(aggregate.counts, { COMPLETED: 1, FAILED: 1, TIMED_OUT: 1 });
});

test('canonical network destinations are rendered without HTTP string heuristics', () => {
  assert.equal(isRuntimeNetworkEvidence({ evidence_type: 'network_destination' }), true);
  assert.equal(isRuntimeNetworkEvidence({ evidence_type: 'dns_destination' }), true);
  assert.equal(isRuntimeNetworkEvidence({ evidence_type: 'httpish_untrusted_text' }), false);
});

test('PDF handler calls the real API and revokes its Blob URL', async () => {
  const source = await readFile(new URL('../src/components/report/InvestigationReportPage.tsx', import.meta.url), 'utf8');
  assert.equal(source.includes('downloadPdfStub'), false);
  assert.equal(source.includes('apiService.downloadApkReportPdf(id)'), true);
  assert.equal(source.includes('URL.createObjectURL(blob)'), true);
  assert.equal(source.includes('URL.revokeObjectURL(blobUrl)'), true);
});

test('static FraudDNA capabilities are not labelled CONFIRMED', async () => {
  const source = await readFile(new URL('../src/components/report/CodeAnalysisTab.tsx', import.meta.url), 'utf8');
  assert.equal(source.includes('value="STATIC MATCH"'), true);
  assert.equal(source.includes('value="CONFIRMED"'), false);
});

test('frontend fallback thresholds match backend bands', () => {
  assert.deepEqual(
    [0, 24, 25, 49, 50, 74, 75, 100].map(severityFromScore),
    ['LOW', 'LOW', 'MEDIUM', 'MEDIUM', 'HIGH', 'HIGH', 'CRITICAL', 'CRITICAL'],
  );
});

test('unsupported similarity search UI is unreachable and removed', async () => {
  const app = await readFile(new URL('../src/App.tsx', import.meta.url), 'utf8');
  const navigation = await readFile(new URL('../src/components/common/TopNavigation.tsx', import.meta.url), 'utf8');
  const oldSearch = new URL('../src/components/search/SearchPage.tsx', import.meta.url);
  assert.equal(app.includes('SearchPage'), false);
  assert.equal(navigation.includes("id: 'search'"), false);
  assert.equal(existsSync(oldSearch), false);
});
