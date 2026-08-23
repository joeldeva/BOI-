import test from 'node:test';
import assert from 'node:assert/strict';
import { extractJobResourceId } from '../src/services/job-contract.mjs';

test('extracts an APK analysis ID from the worker result', () => {
  assert.equal(extractJobResourceId({
    kind: 'apk_analysis',
    status: 'completed',
    result: { analysis_id: 'apk_abc123', resource: '/api/v1/apk-analyses/apk_abc123' },
  }, 'apk_analysis'), 'apk_abc123');
});

test('does not accept a cross-kind, non-terminal, or malformed reference', () => {
  assert.equal(extractJobResourceId({ kind: 'unknown_job', status: 'completed', result: { id: 'x' } }, 'unknown_job'), null);
  assert.equal(extractJobResourceId({ kind: 'apk_analysis', status: 'running', result: { analysis_id: 'apk_x' } }, 'apk_analysis'), null);
  assert.equal(extractJobResourceId({ kind: 'apk_analysis', status: 'completed', result: { resource: 'https://attacker.invalid/api/v1/apk-analyses/apk_x' } }, 'apk_analysis'), null);
});
