import type {
  CapabilitiesResponse,
  DynamicExperimentResult,
  RuntimeEvidence,
} from '../types/api';

export const RUNTIME_NETWORK_EVIDENCE_TYPES: ReadonlySet<string>;
export function isRuntimeReady(capabilities: CapabilitiesResponse | null | undefined): boolean;
export function isRuntimeNetworkEvidence(evidence: RuntimeEvidence | null | undefined): boolean;
export function isReputationEvaluated(reputation: {
  verdict: string;
  providers: unknown[];
} | null | undefined): boolean;
export function knownMaliciousLabel(reputation: {
  verdict: string;
  known_malicious: boolean;
  providers: unknown[];
} | null | undefined): 'NOT EVALUATED' | 'Yes' | 'No';
export function severityFromScore(score: number): 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export function aggregateExperimentStatus(experiments: DynamicExperimentResult[]): {
  status: 'COMPLETED' | 'PARTIAL' | 'FAILED' | 'UNAVAILABLE' | 'TIMED_OUT' | 'SKIPPED';
  counts: Record<string, number>;
  total: number;
};
