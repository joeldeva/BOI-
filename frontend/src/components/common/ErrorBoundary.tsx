import { Component } from 'react';
import type { ErrorInfo, ReactNode } from 'react';

interface ErrorBoundaryProps { children: ReactNode; }
interface ErrorBoundaryState { failed: boolean; }

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): ErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('FraudShield UI render failure', error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.failed) {
      return (
        <main className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6">
          <section className="max-w-lg rounded-xl border border-red-800 bg-slate-900 p-6 space-y-3">
            <h1 className="text-xl font-bold">The analyst interface could not render</h1>
            <p className="text-sm text-slate-300">No backend action was taken. Reload the page; if the issue persists, provide the time and request/job ID to the support owner.</p>
            <button onClick={() => window.location.reload()} className="px-4 py-2 rounded bg-blue-600 text-sm font-bold">Reload safely</button>
          </section>
        </main>
      );
    }
    return this.props.children;
  }
}
