import type {
  HealthResponse,
  CapabilitiesResponse,
  DashboardSummaryResponse,
  ApkAnalysisRecord,
  ThreatIndicatorRecord,
  NewIndicatorPayload,
  ApiErrorResponse,
  JobRecord,
  SubmitApkJobParams,
  JsonObject,
} from '../types/api';
import { extractJobResourceId } from './job-contract.mjs';

export { extractJobResourceId } from './job-contract.mjs';

export class ApiError extends Error {
  code: string;
  details?: JsonObject;
  requestId?: string;
  status: number;

  constructor(message: string, code: string, status: number, requestId?: string, details?: JsonObject) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.details = details;
  }
}

const getBaseUrl = (): string => {
  const envUrl: unknown = import.meta.env.VITE_API_BASE_URL;
  return typeof envUrl === 'string' ? envUrl.trim().replace(/\/+$/, '') : '';
};

const generateRequestId = (): string =>
  `req_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 9)}`;

export const generateIdempotencyKey = (): string => {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `ik_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
};

async function handleResponse<T>(response: Response): Promise<T> {
  const isJson = response.headers.get('content-type')?.includes('application/json') ?? false;
  if (!response.ok) {
    let code = 'http_error';
    let message = `Request failed with status ${response.status} ${response.statusText}`;
    let details: JsonObject | undefined;
    let requestId = response.headers.get('x-request-id') ?? undefined;
    if (isJson) {
      try {
        const errorData = (await response.json()) as ApiErrorResponse;
        code = errorData.error?.code || code;
        message = errorData.error?.message || message;
        details = errorData.error?.details;
        requestId = errorData.error?.request_id || requestId;
      } catch {
        // Retain the transport-level fallback envelope.
      }
    } else {
      const body = await response.text().catch(() => '');
      if (body) message = body;
    }
    throw new ApiError(message, code, response.status, requestId, details);
  }
  if (response.status === 204) return undefined as T;
  return isJson ? ((await response.json()) as T) : (undefined as T);
}

async function request<T>(baseUrl: string, endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${baseUrl}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;
  const headers = new Headers(options.headers);
  if (!headers.has('X-Request-ID')) headers.set('X-Request-ID', generateRequestId());
  if (typeof options.body === 'string' && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  return handleResponse<T>(response);
}

export const apiService = {
  baseUrl: getBaseUrl(),

  fetch<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    return request<T>(this.baseUrl, endpoint, options);
  },

  getHealth(): Promise<HealthResponse> { return this.fetch('/health'); },
  getCapabilities(): Promise<CapabilitiesResponse> { return this.fetch('/api/v1/system/capabilities'); },
  getDashboardSummary(): Promise<DashboardSummaryResponse> { return this.fetch('/api/v1/dashboard/summary'); },

  listApkAnalyses(limit = 50, offset = 0): Promise<{ items: ApkAnalysisRecord[]; total: number }> {
    return this.fetch(`/api/v1/apk-analyses?limit=${limit}&offset=${offset}`);
  },
  getApkAnalysis(id: string): Promise<ApkAnalysisRecord> {
    return this.fetch(`/api/v1/apk-analyses/${encodeURIComponent(id)}`);
  },
  async downloadApkReportPdf(id: string): Promise<Blob> {
    const response = await fetch(`${this.baseUrl}/api/v1/apk-analyses/${encodeURIComponent(id)}/report.pdf`, {
      credentials: 'same-origin',
      headers: { 'X-Request-ID': generateRequestId() },
    });
    if (!response.ok) await handleResponse<never>(response);
    return response.blob();
  },

  listIndicators(limit = 100): Promise<{ items: ThreatIndicatorRecord[]; total: number }> {
    return this.fetch(`/api/v1/indicators?limit=${limit}`);
  },
  createIndicator(payload: NewIndicatorPayload): Promise<ThreatIndicatorRecord> {
    return this.fetch('/api/v1/indicators', { method: 'POST', body: JSON.stringify(payload) });
  },

  analyzeApkInline(
    params: { file: File; category?: string; dynamic?: boolean },
    signal?: AbortSignal
  ): Promise<ApkAnalysisRecord> {
    const body = new FormData();
    body.append('file', params.file);
    body.append('category', params.category ?? 'banking');
    body.append('dynamic', String(params.dynamic ?? false));
    return this.fetch('/api/v1/apk-analyses', { method: 'POST', body, signal });
  },

  submitApkJob(params: SubmitApkJobParams): Promise<JobRecord> {
    const body = new FormData();
    body.append('file', params.file);
    body.append('category', params.category ?? 'banking');
    body.append('dynamic', String(params.dynamic ?? false));
    body.append('priority', String(params.priority ?? 100));
    body.append('max_attempts', String(params.maxAttempts ?? 3));
    const headers = params.idempotencyKey ? { 'Idempotency-Key': params.idempotencyKey } : undefined;
    return this.fetch('/api/v1/jobs/apk-analysis', { method: 'POST', body, headers });
  },
  getJob(jobId: string, signal?: AbortSignal): Promise<JobRecord> {
    return this.fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}`, { signal });
  },
  cancelJob(jobId: string): Promise<JobRecord> {
    return this.fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}/cancel`, { method: 'POST' });
  },
  retryJob(jobId: string): Promise<JobRecord> {
    return this.fetch(`/api/v1/jobs/${encodeURIComponent(jobId)}/retry`, { method: 'POST' });
  },
};

const wait = (milliseconds: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve, reject) => {
    const timer = window.setTimeout(resolve, milliseconds);
    signal?.addEventListener('abort', () => {
      window.clearTimeout(timer);
      reject(new DOMException('Polling was cancelled', 'AbortError'));
    }, { once: true });
  });

export async function pollJob(
  jobId: string,
  onUpdate?: (job: JobRecord) => void,
  maxDuration = 10 * 60_000,
  signal?: AbortSignal,
): Promise<JobRecord> {
  const terminal = new Set(['completed', 'failed', 'cancelled']);
  const started = Date.now();
  let interval = 1_000;
  while (true) {
    signal?.throwIfAborted();
    const job = await apiService.getJob(jobId, signal);
    onUpdate?.(job);
    if (terminal.has(job.status)) return job;
    if (Date.now() - started >= maxDuration) {
      throw new ApiError(`Job ${jobId} did not complete within ${Math.round(maxDuration / 1000)} seconds`, 'polling_timeout', 408);
    }
    await wait(interval, signal);
    interval = Math.min(interval * 2, 8_000);
  }
}

export function requireJobResourceId(job: JobRecord, expectedKind: 'apk_analysis'): string {
  const resourceId = extractJobResourceId(job, expectedKind);
  if (!resourceId) {
    throw new ApiError(`Completed ${expectedKind} job did not include a valid resource reference`, 'invalid_job_result', 502);
  }
  return resourceId;
}
