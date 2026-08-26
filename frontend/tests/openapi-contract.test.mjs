import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';

const specUrl = new URL('../../docs/openapi.json', import.meta.url);
const specExists = existsSync(specUrl);

let spec = null;
if (specExists) {
  spec = JSON.parse(await readFile(specUrl, 'utf8'));
}

test('frontend job endpoints exist with the required HTTP methods', { skip: !specExists && 'OpenAPI specification is only present in repository context' }, () => {
  assert.ok(spec.paths['/api/v1/jobs/apk-analysis']?.post);
  assert.ok(spec.paths['/api/v1/jobs/{job_id}']?.get);
  assert.ok(spec.paths['/api/v1/jobs/{job_id}/cancel']?.post);
  assert.equal(spec.paths['/api/v1/jobs/{job_id}']?.delete, undefined);
});

test('all frontend data routes are present', { skip: !specExists && 'OpenAPI specification is only present in repository context' }, () => {
  const required = [
    '/api/v1/system/capabilities',
    '/api/v1/dashboard/summary',
    '/api/v1/apk-analyses',
    '/api/v1/apk-analyses/{analysis_id}',
    '/api/v1/apk-analyses/{analysis_id}/report.pdf',
    '/api/v1/indicators',
  ];
  for (const route of required) assert.ok(spec.paths[route], `missing OpenAPI route: ${route}`);
});

test('removed v2 non-APK product routes are absent', { skip: !specExists && 'OpenAPI specification is only present in repository context' }, () => {
  for (const route of Object.keys(spec.paths)) {
    assert.equal(route.includes('graph-runs'), false);
    assert.equal(route.includes('transaction-datasets'), false);
    assert.equal(route.includes('graph-analysis'), false);
  }
});

test('removed demo routes are absent from OpenAPI spec', { skip: !specExists && 'OpenAPI specification is only present in repository context' }, () => {
  for (const route of Object.keys(spec.paths)) {
    assert.equal(route.includes('/demo'), false, `Demo route found in OpenAPI spec: ${route}`);
    assert.equal(route.includes('seed-demo'), false, `seed-demo route found in OpenAPI spec: ${route}`);
  }
});

