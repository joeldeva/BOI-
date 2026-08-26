import { useCallback, useEffect, useRef, useState } from 'react';
import { Header } from './components/common/Header';
import { ErrorBanner } from './components/common/ErrorBanner';
import { CommandCenter } from './components/dashboard/CommandCenter';
import { ApkUploadCard } from './components/deceptiscope/ApkUploadCard';
import { ApkAnalysisView } from './components/deceptiscope/ApkAnalysisView';
import { IndicatorStore } from './components/indicators/IndicatorStore';
import { SettingsModal } from './components/settings/SettingsModal';
import {
  apiService,
  ApiError,
  generateIdempotencyKey,
  pollJob,
  requireJobResourceId,
} from './services/api';
import type {
  HealthResponse,
  CapabilitiesResponse,
  DashboardSummaryResponse,
  ApkAnalysisRecord,
  JobRecord,
} from './types/api';

const asError = (value: unknown): Error =>
  value instanceof Error ? value : new Error(typeof value === 'string' ? value : 'Unexpected error');

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [capabilities, setCapabilities] = useState<CapabilitiesResponse | null>(null);
  const [summary, setSummary] = useState<DashboardSummaryResponse | null>(null);
  const [recentApks, setRecentApks] = useState<ApkAnalysisRecord[]>([]);
  const [selectedApk, setSelectedApk] = useState<ApkAnalysisRecord | null>(null);
  const [isUploadingApk, setIsUploadingApk] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [globalError, setGlobalError] = useState<Error | string | null>(null);
  const [apkJob, setApkJob] = useState<JobRecord | null>(null);
  const apkPoll = useRef<AbortController | null>(null);

  const fetchDashboardData = useCallback(async () => {
    const results = await Promise.allSettled([
      apiService.getHealth(),
      apiService.getCapabilities(),
      apiService.getDashboardSummary(),
      apiService.listApkAnalyses(10),
    ] as const);
    const [healthResult, capabilitiesResult, summaryResult, apksResult] = results;
    if (healthResult.status === 'fulfilled') setHealth(healthResult.value);
    if (capabilitiesResult.status === 'fulfilled') setCapabilities(capabilitiesResult.value);
    if (summaryResult.status === 'fulfilled') setSummary(summaryResult.value);
    if (apksResult.status === 'fulfilled') {
      setRecentApks(apksResult.value.items);
      setSelectedApk((current) => current ?? apksResult.value.items[0] ?? null);
    }
    const failure = results.find((result) => result.status === 'rejected');
    if (failure?.status === 'rejected') setGlobalError(asError(failure.reason));
  }, []);

  useEffect(() => {
    void fetchDashboardData();
    return () => apkPoll.current?.abort();
  }, [fetchDashboardData]);

  const handleUploadApk = async (file: File, category: string, dynamic: boolean) => {
    setIsUploadingApk(true);
    setGlobalError(null);
    setApkJob(null);
    apkPoll.current?.abort();
    apkPoll.current = new AbortController();
    try {
      const queued = await apiService.submitApkJob({
        file,
        category: category as 'banking' | 'finance' | 'utility' | 'other',
        dynamic,
        idempotencyKey: generateIdempotencyKey(),
      });
      setApkJob(queued);
      const completed = queued.status === 'completed'
        ? queued
        : await pollJob(queued.id, setApkJob, 10 * 60_000, apkPoll.current.signal);
      if (completed.status === 'failed') {
        throw new ApiError(completed.error_message || 'APK analysis job failed', completed.error_code || 'job_failed', 500);
      }
      if (completed.status === 'cancelled') {
        throw new ApiError('APK analysis job was cancelled', 'job_cancelled', 409);
      }
      const result = await apiService.getApkAnalysis(requireJobResourceId(completed, 'apk_analysis'));
      setSelectedApk(result);
      setActiveTab('deceptiscope');
      await fetchDashboardData();
    } catch (error) {
      setGlobalError(asError(error));
      throw error;
    } finally {
      setIsUploadingApk(false);
    }
  };

  const handleDownloadPdf = async (apkId: string) => {
    try {
      const blob = await apiService.downloadApkReportPdf(apkId);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `deceptiscope-apk-report-${apkId}.pdf`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setGlobalError(asError(error));
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      <Header
        health={health}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onOpenSettings={() => setIsSettingsOpen(true)}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {globalError && <ErrorBanner error={globalError} onDismiss={() => setGlobalError(null)} />}

        {activeTab === 'dashboard' && (
          <CommandCenter
            health={health}
            summary={summary}
            capabilities={capabilities}
            recentApks={recentApks}
            onSelectApk={(id) => {
              void apiService.getApkAnalysis(id).then((record) => {
                setSelectedApk(record);
                setActiveTab('deceptiscope');
              }).catch((error: unknown) => setGlobalError(asError(error)));
            }}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'deceptiscope' && (
          <div className="space-y-6">
            <ApkUploadCard
              onUpload={handleUploadApk}
              isUploading={isUploadingApk}
              capabilities={capabilities}
              jobStatus={apkJob?.status ?? null}
              jobId={apkJob?.id ?? null}
              jobError={apkJob?.error_message ?? null}
            />
            {selectedApk && (
              <ApkAnalysisView analysis={selectedApk} onDownloadPdf={handleDownloadPdf} />
            )}
          </div>
        )}

        {activeTab === 'indicators' && <IndicatorStore onError={setGlobalError} />}
      </main>

      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        capabilities={capabilities}
        onRefreshCapabilities={() => void fetchDashboardData()}
      />
    </div>
  );
}
