export const RUNTIME_NETWORK_EVIDENCE_TYPES = new Set([
  'network_destination',
  'dns_destination',
  'network_connection',
  'dns_query',
  'tls_metadata',
]);

export function isRuntimeReady(capabilities) {
  return capabilities?.dynamic_lite?.runtime_ready === true;
}

export function isRuntimeNetworkEvidence(evidence) {
  return RUNTIME_NETWORK_EVIDENCE_TYPES.has(String(evidence?.evidence_type ?? '').toLowerCase());
}

export function isReputationEvaluated(reputation) {
  return reputation?.verdict !== 'not-queried' && (reputation?.providers?.length ?? 0) > 0;
}

export function knownMaliciousLabel(reputation) {
  if (!isReputationEvaluated(reputation)) return 'NOT EVALUATED';
  return reputation.known_malicious ? 'Yes' : 'No';
}

export function severityFromScore(score) {
  if (score >= 75) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 25) return 'MEDIUM';
  return 'LOW';
}

export function aggregateExperimentStatus(experiments) {
  const counts = {};
  for (const experiment of experiments ?? []) {
    const status = String(experiment?.status ?? 'UNAVAILABLE').toUpperCase();
    counts[status] = (counts[status] ?? 0) + 1;
  }

  const statuses = Object.keys(counts);
  const total = experiments?.length ?? 0;
  let status = 'UNAVAILABLE';
  if (total === 0) status = 'UNAVAILABLE';
  else if (counts.COMPLETED === total) status = 'COMPLETED';
  else if ((counts.SKIPPED ?? 0) + (counts.NOT_RUN ?? 0) + (counts.DISABLED ?? 0) === total) status = 'SKIPPED';
  else if ((counts.UNAVAILABLE ?? 0) + (counts.UNSUPPORTED ?? 0) === total) status = 'UNAVAILABLE';
  else if (counts.TIMED_OUT === total) status = 'TIMED_OUT';
  else if ((counts.COMPLETED ?? 0) > 0 || statuses.length > 1) status = 'PARTIAL';
  else if ((counts.FAILED ?? 0) > 0) status = 'FAILED';
  else if ((counts.TIMED_OUT ?? 0) > 0) status = 'TIMED_OUT';
  else status = 'PARTIAL';

  return { status, counts, total };
}
