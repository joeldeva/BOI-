import React, { useState, useRef } from 'react';
import { Upload, Smartphone, AlertTriangle, RefreshCw } from 'lucide-react';
import type { CapabilitiesResponse, JobStatus } from '../../types/api';
import { JobStatusBadge } from '../common/JobStatusBadge';

interface ApkUploadCardProps {
  onUpload: (file: File, category: string, dynamic: boolean) => Promise<void>;
  isUploading: boolean;
  capabilities: CapabilitiesResponse | null;
  jobStatus?: JobStatus | null;
  jobId?: string | null;
  jobError?: string | null;
}

export const ApkUploadCard: React.FC<ApkUploadCardProps> = ({
  onUpload,
  isUploading,
  capabilities,
  jobStatus,
  jobId,
  jobError,
}) => {
  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [category, setCategory] = useState<string>('banking');
  const [dynamic, setDynamic] = useState<boolean>(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const configuredMax = Number(import.meta.env.VITE_MAX_APK_MB ?? 75);
  const maxMb = Number.isFinite(configuredMax) && configuredMax > 0 ? configuredMax : 75;

  const categories = [
    { id: 'banking', label: 'Banking & Financial (Default)' },
    { id: 'finance', label: 'Finance / Payment' },
    { id: 'utility', label: 'System Utility / Tool' },
    { id: 'other', label: 'General / Other' },
  ];

  const handleFileSelect = (file: File) => {
    setLocalError(null);
    if (!file.name.toLowerCase().endsWith('.apk')) {
      setLocalError('File must have .apk extension.');
      return;
    }
    if (file.size > maxMb * 1024 * 1024) {
      setLocalError(`File size exceeds maximum threshold of ${maxMb} MB.`);
      return;
    }
    setSelectedFile(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (!selectedFile) return;
    try {
      await onUpload(selectedFile, category, dynamic);
      setSelectedFile(null);
    } catch {
      // Error handled by parent component banner
    }
  };

  return (
    <div className="soc-card p-6 space-y-5">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Smartphone className="w-5 h-5 text-blue-400" />
          <h2 className="text-base font-bold text-white">Upload Android APK Package</h2>
        </div>
        <span className="text-xs font-mono text-slate-400">
          DeceptiScope Engine v3.0
        </span>
      </div>

      {localError && (
        <div className="p-3 rounded bg-red-950/40 border border-red-800/50 text-red-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{localError}</span>
        </div>
      )}

      {/* Drag & Drop Target Area */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-all ${
          dragOver
            ? 'border-blue-500 bg-blue-500/10'
            : selectedFile
            ? 'border-emerald-500/50 bg-emerald-500/5'
            : 'border-slate-800 hover:border-slate-700 bg-slate-950/50'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".apk"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files[0]) {
              handleFileSelect(e.target.files[0]);
            }
          }}
        />

        <div className="flex flex-col items-center gap-3">
          <div className="p-3 rounded-full bg-slate-900 border border-slate-800 text-blue-400">
            <Upload className="w-6 h-6" />
          </div>

          {selectedFile ? (
            <div className="space-y-1">
              <p className="text-sm font-bold text-emerald-400 font-mono">
                {selectedFile.name}
              </p>
              <p className="text-xs text-slate-400 font-mono">
                {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="text-sm font-semibold text-white">
                Drag and drop your target <code className="text-blue-400 font-mono">.apk</code> file here, or click to browse
              </p>
              <p className="text-xs text-slate-400">
                Max file size: {maxMb} MB. Decompress and static DEX/manifest parser active.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Analysis Parameters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-slate-300">
            Declared App Category (for Fraud Delta baseline):
          </label>
          <select
            value={category}
            onChange={(e) => setCategory(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-medium text-white focus:outline-none focus:border-blue-500"
          >
            {categories.map((cat) => (
              <option key={cat.id} value={cat.id}>
                {cat.label}
              </option>
            ))}
          </select>
        </div>

        <div className="space-y-1.5">
          <label className="text-xs font-semibold text-slate-300 flex items-center justify-between">
            <span>Dynamic-lite isolated emulator:</span>
            <span
              className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                capabilities?.dynamic_lite.enabled
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400 border border-slate-700'
              }`}
            >
              {capabilities?.dynamic_lite.enabled ? 'AVAILABLE' : 'OFFLINE'}
            </span>
          </label>
          <label className="flex items-center gap-2 p-2 rounded-lg bg-slate-950 border border-slate-800 cursor-pointer text-xs text-slate-300">
            <input
              type="checkbox"
              checked={dynamic}
              onChange={(e) => setDynamic(e.target.checked)}
              disabled={!capabilities?.dynamic_lite.enabled}
              className="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-blue-500"
            />
            <span>Collect bounded ADB runtime signals in the configured safe target</span>
          </label>
        </div>
      </div>

      {/* Submit Button + Job Status */}
      <div className="flex flex-col gap-3">
        <div className="flex justify-end">
          <button
            onClick={handleSubmit}
            disabled={!selectedFile || isUploading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white shadow-lg shadow-blue-600/25 transition-all disabled:opacity-40"
          >
            {isUploading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Running bounded multi-engine analysis...
              </>
            ) : (
              <>
                <Smartphone className="w-4 h-4" />
                Run DeceptiScope Analysis
              </>
            )}
          </button>
        </div>
        {jobStatus && (
          <div className="flex justify-end">
            <JobStatusBadge status={jobStatus} jobId={jobId ?? undefined} errorMessage={jobError} />
          </div>
        )}
      </div>
    </div>
  );
};
