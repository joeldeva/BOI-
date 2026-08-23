const patterns = {
  apk_analysis: /^\/api\/v1\/apk-analyses\/(apk_[A-Za-z0-9_-]+)$/,
};

export function extractJobResourceId(job, expectedKind) {
  if (!job || job.status !== 'completed' || job.kind !== expectedKind || !job.result) return null;
  if (expectedKind !== 'apk_analysis') return null;
  const direct = job.result.analysis_id;
  if (typeof direct === 'string' && direct.length > 0) return direct;
  if (typeof job.result.resource !== 'string') return null;
  return job.result.resource.match(patterns[expectedKind])?.[1] ?? null;
}
