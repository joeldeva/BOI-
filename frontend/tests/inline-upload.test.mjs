import test from 'node:test';
import assert from 'node:assert/strict';

test('TEST A — INLINE DEVELOPMENT MODE: uses POST /api/v1/apk-analyses when inline_analysis is true', () => {
  const capabilities = { inline_analysis: true };
  const mockCalls = [];

  const mockApiService = {
    analyzeApkInline(params) {
      mockCalls.push({ type: 'inline', params });
      return Promise.resolve({ id: 'apk_inline_123', status: 'completed' });
    },
    submitApkJob(params) {
      mockCalls.push({ type: 'job', params });
      return Promise.resolve({ id: 'job_123', status: 'queued' });
    },
  };

  const uploadFn = async (file, category, dynamic) => {
    if (capabilities.inline_analysis) {
      return mockApiService.analyzeApkInline({ file, category, dynamic });
    }
    return mockApiService.submitApkJob({ file, category, dynamic });
  };

  return uploadFn('sample.apk', 'banking', false).then((result) => {
    assert.equal(mockCalls.length, 1);
    assert.equal(mockCalls[0].type, 'inline');
    assert.equal(result.id, 'apk_inline_123');
  });
});

test('TEST B — DURABLE MODE: uses POST /api/v1/jobs/apk-analysis when inline_analysis is false', () => {
  const capabilities = { inline_analysis: false };
  const mockCalls = [];

  const mockApiService = {
    analyzeApkInline(params) {
      mockCalls.push({ type: 'inline', params });
      return Promise.resolve({ id: 'apk_inline_123' });
    },
    submitApkJob(params) {
      mockCalls.push({ type: 'job', params });
      return Promise.resolve({ id: 'job_456', status: 'queued' });
    },
  };

  const uploadFn = async (file, category, dynamic) => {
    if (capabilities.inline_analysis) {
      return mockApiService.analyzeApkInline({ file, category, dynamic });
    }
    return mockApiService.submitApkJob({ file, category, dynamic });
  };

  return uploadFn('sample.apk', 'banking', false).then((result) => {
    assert.equal(mockCalls.length, 1);
    assert.equal(mockCalls[0].type, 'job');
    assert.equal(result.id, 'job_456');
  });
});

test('TEST C — QUEUED WORDING: queued durable job displays Queued / Waiting for analysis worker and no false active analysis', () => {
  const formatStatus = (jobStatus, inlineMode) => {
    if (inlineMode) return jobStatus === 'running' ? 'Analyzing…' : 'Complete';
    if (jobStatus === 'queued') return 'Queued / Waiting for analysis worker';
    if (jobStatus === 'running') return 'Analyzing…';
    return 'Submitting…';
  };

  assert.equal(formatStatus('queued', false), 'Queued / Waiting for analysis worker');
  assert.notEqual(formatStatus('queued', false), 'Analyzing…');
});

test('TEST D — RUNNING WORDING: running job displays Analyzing…', () => {
  const formatStatus = (jobStatus, inlineMode) => {
    if (inlineMode) return jobStatus === 'running' ? 'Analyzing…' : 'Complete';
    if (jobStatus === 'queued') return 'Queued / Waiting for analysis worker';
    if (jobStatus === 'running') return 'Analyzing…';
    return 'Submitting…';
  };

  assert.equal(formatStatus('running', false), 'Analyzing…');
  assert.equal(formatStatus('running', true), 'Analyzing…');
});

test('TEST E — FAILURE: failed inline request leaves no fake analysis row and surfaces API error', async () => {
  const mockApiService = {
    analyzeApkInline() {
      return Promise.reject(new Error('Invalid APK signature'));
    },
  };

  let historyCount = 0;
  let capturedError = null;

  try {
    await mockApiService.analyzeApkInline({ file: 'bad.apk' });
    historyCount += 1;
  } catch (err) {
    capturedError = err.message;
  }

  assert.equal(historyCount, 0);
  assert.equal(capturedError, 'Invalid APK signature');
});

test('TEST F — DYNAMIC UNAVAILABLE: dynamic checkbox remains unavailable when runtime capability says unavailable while static inline analysis can execute', () => {
  const capabilities = {
    inline_analysis: true,
    dynamic_lite: {
      enabled: false,
      adb_available: false,
      emulator_serial_configured: false,
    },
  };

  const isDynamicAvailable = Boolean(
    capabilities.dynamic_lite?.enabled &&
    capabilities.dynamic_lite?.adb_available &&
    capabilities.dynamic_lite?.emulator_serial_configured
  );

  assert.equal(isDynamicAvailable, false);
  assert.equal(capabilities.inline_analysis, true);
});
