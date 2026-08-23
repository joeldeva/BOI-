import React, { useState } from 'react';
import { AlertTriangle, Copy, Check, X } from 'lucide-react';
import { ApiError } from '../../services/api';

interface ErrorBannerProps {
  error: ApiError | Error | string | null;
  onDismiss?: () => void;
  className?: string;
}

export const ErrorBanner: React.FC<ErrorBannerProps> = ({
  error,
  onDismiss,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  if (!error) return null;

  let message = 'An unexpected error occurred.';
  let code = 'ERROR';
  let requestId: string | undefined;
  let details: Record<string, any> | undefined;

  if (error instanceof ApiError) {
    message = error.message;
    code = error.code;
    requestId = error.requestId;
    details = error.details;
  } else if (error instanceof Error) {
    message = error.message;
  } else if (typeof error === 'string') {
    message = error;
  }

  const handleCopyRequestId = () => {
    if (requestId) {
      navigator.clipboard.writeText(requestId);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className={`p-4 rounded-lg bg-red-950/40 border border-red-800/50 text-red-200 ${className}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 mt-0.5 shrink-0" />
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-red-900/60 text-red-300 border border-red-700/50">
                {code}
              </span>
              <p className="text-sm font-semibold text-red-100">{message}</p>
            </div>

            {requestId && (
              <div className="flex items-center gap-2 text-xs text-red-300/80 font-mono mt-1">
                <span>Request ID: <span className="text-red-200">{requestId}</span></span>
                <button
                  onClick={handleCopyRequestId}
                  className="p-1 hover:bg-red-900/50 rounded transition-colors text-red-300"
                  title="Copy Request ID for troubleshooting"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            )}

            {details && Object.keys(details).length > 0 && (
              <details className="mt-2 text-xs font-mono text-red-300/90 bg-red-950/60 p-2 rounded border border-red-900/40">
                <summary className="cursor-pointer font-sans font-medium text-red-400 hover:text-red-300">
                  View Technical Error Details
                </summary>

                  {JSON.stringify(details, null, 2)}

              </details>
            )}
          </div>
        </div>

        {onDismiss && (
          <button
            onClick={onDismiss}
            className="p-1 text-red-400 hover:text-red-200 hover:bg-red-900/40 rounded"
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
};
