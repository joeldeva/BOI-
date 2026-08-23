import type { JobRecord, JobType } from '../types/api';

export function extractJobResourceId(job: JobRecord, expectedKind: JobType): string | null;
