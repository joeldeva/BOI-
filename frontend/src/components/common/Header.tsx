import React from 'react';
import { Shield, Activity, Settings, Database, Smartphone } from 'lucide-react';
import type { HealthResponse } from '../../types/api';

interface HeaderProps {
  health: HealthResponse | null;
  activeTab: string;
  onSelectTab: (tab: string) => void;
  onOpenSettings: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  health,
  activeTab,
  onSelectTab,
  onOpenSettings,
}) => {
  const isHealthy = health?.status === 'healthy';

  const navItems = [
    { id: 'dashboard', label: 'Command Center', icon: Activity },
    { id: 'deceptiscope', label: 'DeceptiScope (APK)', icon: Smartphone },
    { id: 'indicators', label: 'Indicator Store', icon: Database },
  ];

  return (
    <header className="bg-slate-900 border-b border-slate-800 sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => onSelectTab('dashboard')}>
            <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-display font-extrabold text-lg text-white tracking-tight">
                  FraudShield
                </span>
                <span className="text-[10px] font-mono font-bold bg-blue-500/20 text-blue-400 border border-blue-500/30 px-1.5 py-0.5 rounded">
                  v{health?.version ?? '3.0.0'}
                </span>
              </div>
              <p className="text-[11px] text-slate-400 tracking-wide">
                Multi-Engine Android Threat Intelligence
              </p>
            </div>
          </div>

          {/* Navigation Bar */}
          <nav className="hidden md:flex items-center gap-1 bg-slate-950/60 p-1.5 rounded-lg border border-slate-800">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/25 border border-blue-500'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          {/* Actions & Live Health Indicator */}
          <div className="flex items-center gap-3">
            {/* Health Status Indicator */}
            <div
              className={`hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-semibold border ${
                isHealthy
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : 'bg-red-500/10 text-red-400 border-red-500/30'
              }`}
              title={`Database: ${health?.database || 'unknown'}`}
            >
              <span className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
              <span>{isHealthy ? 'Backend: Online' : 'Backend: Offline'}</span>
            </div>

            {/* Settings Modal Button */}
            <button
              onClick={onOpenSettings}
              className="p-2 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors border border-slate-800"
              title="Platform Capability & Connection Settings"
            >
              <Settings className="w-4 h-4" />
            </button>
          </div>
        </div>
        <nav className="md:hidden flex items-center gap-1 overflow-x-auto pb-2" aria-label="Mobile navigation">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button key={item.id} onClick={() => onSelectTab(item.id)} className={`shrink-0 flex items-center gap-1.5 px-2.5 py-1.5 rounded text-[11px] font-semibold ${isActive ? 'bg-blue-600 text-white' : 'bg-slate-950 text-slate-400'}`}>
                <Icon className="w-3.5 h-3.5" />{item.label}
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
