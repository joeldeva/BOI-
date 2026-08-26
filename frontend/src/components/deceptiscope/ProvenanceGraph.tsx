import React, { useState, useMemo, useRef } from 'react';
import {
  ArrowRight,
  BrainCircuit,
  Check,
  ChevronRight,
  Copy,
  Cpu,
  FileCode,
  Flame,
  Globe,
  Info,
  Key,
  Layers,
  Maximize2,
  Minimize2,
  RefreshCw,
  Smartphone,
  X,
  Zap,
} from 'lucide-react';
import type { ApkAnalysisResult } from '../../types/api';
import {
  buildProvenanceGraph,
  type ProvenanceGraphData,
  type ProvenanceNode,
  type ProvenanceNodeType,
  type ProvenanceState,
} from '../../types/provenanceGraph';

/* =========================================================================
   Visual Styling & Icon Configuration
   ========================================================================= */

const LAYER_TITLES = [
  { title: '1. Manifest & Perms', subtitle: 'Declared Capabilities', color: 'text-blue-400', border: 'border-blue-500/30' },
  { title: '2. Components & APIs', subtitle: 'DEX Implementation', color: 'text-cyan-400', border: 'border-cyan-500/30' },
  { title: '3. Data & Runtime', subtitle: 'Sandbox Observations', color: 'text-emerald-400', border: 'border-emerald-500/30' },
  { title: '4. C2 & Behaviors', subtitle: 'Exfiltration & Attacks', color: 'text-violet-400', border: 'border-violet-500/30' },
  { title: '5. Banking Impact', subtitle: 'Direct Fraud Risk', color: 'text-red-400', border: 'border-red-500/40' },
];

function getNodeIcon(type: ProvenanceNodeType) {
  switch (type) {
    case 'PERMISSION':
      return Key;
    case 'COMPONENT':
      return Smartphone;
    case 'API':
      return Cpu;
    case 'DATA':
      return FileCode;
    case 'RUNTIME_EVENT':
      return Zap;
    case 'NETWORK':
      return Globe;
    case 'BEHAVIOR':
      return BrainCircuit;
    case 'BANKING_IMPACT':
      return Flame;
    default:
      return Info;
  }
}

function getStateBadgeStyle(state: ProvenanceState) {
  switch (state) {
    case 'STATIC':
      return {
        badge: 'bg-blue-950/60 text-blue-300 border-blue-500/30',
        card: 'border-slate-800 bg-slate-950/90 hover:border-blue-500/60',
        glow: 'hover:shadow-[0_0_15px_rgba(59,130,246,0.15)]',
        label: 'STATIC EVIDENCE',
        dot: 'bg-blue-400',
      };
    case 'RUNTIME_CONFIRMED':
      return {
        badge: 'bg-emerald-950/70 text-emerald-300 border-emerald-500/50 shadow-[0_0_10px_rgba(16,185,129,0.2)]',
        card: 'border-emerald-500/40 bg-emerald-950/20 hover:border-emerald-400',
        glow: 'shadow-[0_0_18px_rgba(16,185,129,0.12)] hover:shadow-[0_0_22px_rgba(16,185,129,0.25)]',
        label: 'RUNTIME CONFIRMED',
        dot: 'bg-emerald-400 animate-pulse',
      };
    case 'INFERRED':
      return {
        badge: 'bg-violet-950/60 text-violet-300 border-violet-500/30',
        card: 'border-slate-800 bg-slate-950/90 hover:border-violet-500/60',
        glow: 'hover:shadow-[0_0_15px_rgba(139,92,246,0.15)]',
        label: 'INFERRED ATTACK',
        dot: 'bg-violet-400',
      };
    case 'IMPACT':
      return {
        badge: 'bg-red-950/80 text-red-300 border-red-500/60 shadow-[0_0_12px_rgba(239,68,68,0.25)]',
        card: 'border-red-500/50 bg-gradient-to-br from-red-950/30 via-slate-950 to-slate-950 hover:border-red-400',
        glow: 'shadow-[0_0_20px_rgba(239,68,68,0.15)] hover:shadow-[0_0_25px_rgba(239,68,68,0.3)]',
        label: 'BANKING IMPACT',
        dot: 'bg-red-500 animate-ping',
      };
    case 'CONTRADICTED':
      return {
        badge: 'bg-slate-900 text-slate-400 border-slate-700',
        card: 'border-slate-800/60 bg-slate-950/50 opacity-60',
        glow: '',
        label: 'CONTRADICTED',
        dot: 'bg-slate-500',
      };
  }
}

/* =========================================================================
   Component
   ========================================================================= */

interface ProvenanceGraphProps {
  result: ApkAnalysisResult | null | undefined;
}

export function ProvenanceGraph({ result }: ProvenanceGraphProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);
  const [filterState, setFilterState] = useState<'ALL' | 'CONFIRMED' | 'STATIC' | 'IMPACT'>('ALL');
  const [activeImpactFocus, setActiveImpactFocus] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [copiedEvidenceId, setCopiedEvidenceId] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const graphData: ProvenanceGraphData = useMemo(() => buildProvenanceGraph(result), [result]);

  const { nodes, edges, summary, impactNodes } = graphData;

  // Selected Node Details
  const selectedNode = useMemo(
    () => (selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) || null : null),
    [selectedNodeId, nodes]
  );

  // Causal-path traversal for highlighting prerequisites and consequences.
  const highlightedNodeIds = useMemo(() => {
    const focusId = activeImpactFocus || hoveredNodeId || selectedNodeId;
    if (!focusId) return new Set<string>();

    const activeNodeIds = new Set<string>([focusId]);

    const findPreconditions = (targetId: string) => {
      for (const edge of edges) {
        if (edge.target === targetId) {
          if (!activeNodeIds.has(edge.source)) {
            activeNodeIds.add(edge.source);
            findPreconditions(edge.source);
          }
        }
      }
    };

    const findConsequences = (sourceId: string) => {
      for (const edge of edges) {
        if (edge.source === sourceId) {
          if (!activeNodeIds.has(edge.target)) {
            activeNodeIds.add(edge.target);
            findConsequences(edge.target);
          }
        }
      }
    };

    findPreconditions(focusId);
    findConsequences(focusId);

    return activeNodeIds;
  }, [activeImpactFocus, hoveredNodeId, selectedNodeId, edges]);

  // Group nodes by Layer (0 to 4)
  const layerGroups = useMemo(() => {
    const groups: ProvenanceNode[][] = [[], [], [], [], []];
    for (const node of nodes) {
      if (filterState === 'CONFIRMED' && node.state !== 'RUNTIME_CONFIRMED' && node.state !== 'IMPACT') continue;
      if (filterState === 'STATIC' && node.state !== 'STATIC') continue;
      if (filterState === 'IMPACT' && node.state !== 'IMPACT' && !highlightedNodeIds.has(node.id)) continue;
      const l = Math.min(Math.max(node.layer, 0), 4);
      groups[l].push(node);
    }
    return groups;
  }, [nodes, filterState, highlightedNodeIds]);

  const handleCopyEvidence = (id: string) => {
    void navigator.clipboard.writeText(id);
    setCopiedEvidenceId(id);
    window.setTimeout(() => setCopiedEvidenceId(null), 2000);
  };

  if (!result || nodes.length === 0) {
    return (
      <section className="soc-card p-6 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
          <Layers className="w-5 h-5 text-blue-400" />
          <h3 className="text-base font-bold text-white">Evidence-to-Banking Impact Provenance Graph</h3>
        </div>
        <div className="flex flex-col items-center justify-center py-10 text-center">
          <BrainCircuit className="w-10 h-10 text-slate-600 mb-3" />
          <p className="text-sm font-bold text-slate-400">Provenance data not available for this record</p>
          <p className="text-xs text-slate-500 mt-1 max-w-sm">
            Upload and analyze an APK to visualize the end-to-end evidence graph.
          </p>
        </div>
      </section>
    );
  }

  return (
    <section
      ref={containerRef}
      className={`soc-card p-6 space-y-5 transition-all duration-300 ${
        isFullscreen ? 'fixed inset-4 z-50 overflow-y-auto bg-slate-950 shadow-2xl border-blue-500/50' : ''
      }`}
    >
      {/* Header & Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="space-y-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="p-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-lg font-display font-extrabold text-white">
                  Evidence-to-Banking Impact Provenance Graph
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-950/70 border border-blue-500/30 text-blue-300">
                  PRIMARY DIFFERENTIATOR
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Deterministic provenance tracing: Shows exactly <strong>why</strong> technical evidence creates banking fraud risk.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Tools */}
        <div className="flex items-center gap-2 flex-wrap shrink-0">
          {/* State Filter Buttons */}
          <div className="flex items-center p-1 bg-slate-900/90 border border-slate-800 rounded-lg text-xs">
            <button
              onClick={() => {
                setFilterState('ALL');
                setActiveImpactFocus(null);
              }}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                filterState === 'ALL' && !activeImpactFocus ? 'bg-blue-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              All ({summary.totalNodes})
            </button>
            <button
              onClick={() => {
                setFilterState('CONFIRMED');
                setActiveImpactFocus(null);
              }}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                filterState === 'CONFIRMED' ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-emerald-300'
              }`}
            >
              Runtime Verified ({summary.confirmedCount})
            </button>
            <button
              onClick={() => {
                setFilterState('STATIC');
                setActiveImpactFocus(null);
              }}
              className={`px-2.5 py-1 rounded font-medium transition-all ${
                filterState === 'STATIC' ? 'bg-slate-700 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Static ({summary.staticCount})
            </button>
          </div>

          <button
            onClick={() => {
              setActiveImpactFocus(null);
              setSelectedNodeId(null);
              setFilterState('ALL');
            }}
            title="Reset highlights"
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white"
          >
            <RefreshCw className="w-4 h-4" />
          </button>

          <button
            onClick={() => setIsFullscreen(!isFullscreen)}
            title={isFullscreen ? 'Exit full screen' : 'Expand full screen'}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-white"
          >
            {isFullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
        </div>
      </div>

      {/* Impact Quick Focus Pills */}
      {impactNodes.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap text-xs pt-1">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500 flex items-center gap-1">
            <Flame className="w-3.5 h-3.5 text-red-400" /> Focus Impact Path:
          </span>
          {impactNodes.map((impact) => {
            const isFocused = activeImpactFocus === impact.id;
            return (
              <button
                key={impact.id}
                onClick={() => {
                  if (isFocused) {
                    setActiveImpactFocus(null);
                  } else {
                    setActiveImpactFocus(impact.id);
                    setSelectedNodeId(impact.id);
                  }
                }}
                className={`px-2.5 py-1 rounded-full border text-xs font-bold transition-all flex items-center gap-1.5 ${
                  isFocused
                    ? 'bg-red-600 text-white border-red-400 shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                    : 'bg-red-950/30 text-red-300 border-red-500/30 hover:border-red-500/70 hover:bg-red-950/60'
                }`}
              >
                <span>{impact.label}</span>
                <ChevronRight className="w-3 h-3 opacity-70" />
              </button>
            );
          })}
          {activeImpactFocus && (
            <button
              onClick={() => setActiveImpactFocus(null)}
              className="text-[11px] text-slate-400 hover:text-white underline pl-2"
            >
              Clear path focus
            </button>
          )}
        </div>
      )}

      {/* Main Multi-Layer Graph Stage */}
      <div className="relative overflow-x-auto pb-4 pt-2">
        <div className="min-w-[1020px] grid grid-cols-5 gap-4 relative">
          {layerGroups.map((groupNodes, layerIndex) => {
            const layerMeta = LAYER_TITLES[layerIndex];
            return (
              <div key={layerIndex} className="flex flex-col space-y-3">
                {/* Column Layer Header */}
                <div className={`p-2.5 rounded-lg bg-slate-950/80 border ${layerMeta.border} text-center space-y-0.5`}>
                  <p className={`text-xs font-extrabold uppercase tracking-wider ${layerMeta.color}`}>
                    {layerMeta.title}
                  </p>
                  <p className="text-[10px] text-slate-400">{layerMeta.subtitle}</p>
                </div>

                {/* Node Cards Container */}
                <div className="space-y-3 min-h-[300px]">
                  {groupNodes.length === 0 ? (
                    <div className="h-32 rounded-lg border border-dashed border-slate-800 flex items-center justify-center text-center p-3 text-[11px] text-slate-600">
                      No nodes matching filter
                    </div>
                  ) : (
                    groupNodes.map((node) => {
                      const NodeIcon = getNodeIcon(node.type);
                      const style = getStateBadgeStyle(node.state);
                      const isSelected = selectedNodeId === node.id;
                      const isHighlighted = highlightedNodeIds.has(node.id);
                      const isDimmed =
                        (activeImpactFocus || hoveredNodeId || selectedNodeId) &&
                        !isHighlighted;

                      return (
                        <div
                          key={node.id}
                          onClick={() => setSelectedNodeId(node.id)}
                          onMouseEnter={() => setHoveredNodeId(node.id)}
                          onMouseLeave={() => setHoveredNodeId(null)}
                          className={`soc-card p-3.5 space-y-2 cursor-pointer transition-all duration-200 relative group ${
                            style.card
                          } ${style.glow} ${
                            isSelected ? 'ring-2 ring-blue-400 border-blue-400 shadow-lg scale-[1.02]' : ''
                          } ${isHighlighted && !isSelected ? 'ring-1 ring-amber-400/70 border-amber-400/80' : ''} ${
                            isDimmed ? 'opacity-35 scale-[0.98]' : 'opacity-100'
                          }`}
                        >
                          {/* Node Header (Type + State Badge) */}
                          <div className="flex items-start justify-between gap-1.5">
                            <div className="flex items-center gap-1.5 min-w-0">
                              <div className="p-1 rounded bg-slate-900/90 border border-slate-800 text-slate-300">
                                <NodeIcon className="w-3.5 h-3.5" />
                              </div>
                              <span className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-tight truncate">
                                {node.type.replaceAll('_', ' ')}
                              </span>
                            </div>
                            <span
                              className={`px-1.5 py-0.5 rounded border text-[9px] font-mono font-extrabold tracking-wider shrink-0 flex items-center gap-1 ${style.badge}`}
                            >
                              <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                              {node.state === 'RUNTIME_CONFIRMED'
                                ? 'VERIFIED'
                                : node.state === 'IMPACT'
                                ? 'IMPACT'
                                : node.state}
                            </span>
                          </div>

                          {/* Node Main Label & Sublabel */}
                          <div>
                            <h4 className="text-xs font-bold text-white leading-snug group-hover:text-blue-300 transition-colors">
                              {node.label}
                            </h4>
                            {node.sublabel && (
                              <p className="text-[10px] text-slate-400 mt-0.5 truncate">{node.sublabel}</p>
                            )}
                          </div>

                          {/* Node Bottom Footer (Evidence ID & Confidence) */}
                          <div className="flex items-center justify-between gap-1 pt-1 border-t border-slate-800/80 text-[10px] font-mono">
                            {node.evidenceId && (
                              <span className="text-slate-500 truncate" title={`Evidence ID: ${node.evidenceId}`}>
                                #{node.evidenceId}
                              </span>
                            )}
                            {node.confidence != null && (
                              <span
                                className={`font-bold ${
                                  node.confidence >= 0.9
                                    ? 'text-emerald-400'
                                    : node.confidence >= 0.75
                                    ? 'text-amber-400'
                                    : 'text-blue-400'
                                }`}
                              >
                                {(node.confidence * 100).toFixed(0)}% conf
                              </span>
                            )}
                          </div>

                          {/* Connected Edge Indicator Arrow on Hover */}
                          <div className="absolute -right-2 top-1/2 -translate-y-1/2 opacity-0 group-hover:opacity-100 transition-opacity hidden sm:block">
                            <div className="p-0.5 rounded-full bg-blue-500 text-white shadow-md">
                              <ArrowRight className="w-2.5 h-2.5" />
                            </div>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Selected Node Provenance Inspector Panel */}
      {selectedNode && (
        <div className="mt-4 p-5 rounded-xl bg-slate-950 border border-blue-500/40 shadow-2xl relative space-y-4 animate-in fade-in duration-200">
          <div className="flex items-start justify-between gap-4 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/20 border border-blue-500/30 text-blue-400">
                {React.createElement(getNodeIcon(selectedNode.type), { className: 'w-5 h-5' })}
              </div>
              <div>
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono font-bold text-slate-400 uppercase">
                    PROVENANCE INSPECTOR // {selectedNode.type}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded border text-[10px] font-mono font-bold ${
                      getStateBadgeStyle(selectedNode.state).badge
                    }`}
                  >
                    {selectedNode.state}
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-0.5">{selectedNode.label}</h3>
              </div>
            </div>

            <button
              onClick={() => setSelectedNodeId(null)}
              className="p-1 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            {/* Column 1: Description & Technical Role */}
            <div className="md:col-span-2 space-y-3">
              <div className="space-y-1">
                <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">Technical Role & Finding</p>
                <p className="text-slate-300 leading-relaxed bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                  {selectedNode.description}
                </p>
              </div>

              {/* Causality Flow */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800/80 space-y-1">
                  <p className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                    <ArrowRight className="w-3 h-3 text-blue-400 rotate-180" /> Preconditions:
                  </p>
                  <div className="space-y-1">
                    {edges
                      .filter((e) => e.target === selectedNode.id)
                      .map((e) => {
                        const src = nodes.find((n) => n.id === e.source);
                        return (
                          <button
                            key={e.id}
                            onClick={() => setSelectedNodeId(e.source)}
                            className="w-full text-left font-mono text-[11px] text-blue-300 hover:text-blue-200 hover:underline truncate block"
                          >
                            ← {src?.label || e.source} ({e.label})
                          </button>
                        );
                      })}
                    {edges.filter((e) => e.target === selectedNode.id).length === 0 && (
                      <p className="text-[11px] text-slate-500 font-mono">Root manifest permission</p>
                    )}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800/80 space-y-1">
                  <p className="text-[10px] font-bold text-slate-400 uppercase flex items-center gap-1">
                    <ArrowRight className="w-3 h-3 text-red-400" /> Consequences:
                  </p>
                  <div className="space-y-1">
                    {edges
                      .filter((e) => e.source === selectedNode.id)
                      .map((e) => {
                        const tgt = nodes.find((n) => n.id === e.target);
                        return (
                          <button
                            key={e.id}
                            onClick={() => setSelectedNodeId(e.target)}
                            className="w-full text-left font-mono text-[11px] text-red-300 hover:text-red-200 hover:underline truncate block"
                          >
                            → {tgt?.label || e.target} ({e.label})
                          </button>
                        );
                      })}
                    {edges.filter((e) => e.source === selectedNode.id).length === 0 && (
                      <p className="text-[11px] text-slate-500 font-mono">Terminal banking fraud impact</p>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Column 2: Structured Metadata & Provenance Evidence */}
            <div className="space-y-3 bg-slate-900/40 p-3 rounded-lg border border-slate-800">
              <div className="space-y-1">
                <p className="text-[10px] font-bold text-slate-400 uppercase">Evidence Identifier</p>
                <div className="flex items-center justify-between gap-2 p-2 rounded bg-slate-950 border border-slate-800 font-mono">
                  <span className="font-bold text-cyan-300">{selectedNode.evidenceId || 'N/A'}</span>
                  {selectedNode.evidenceId && (
                    <button
                      onClick={() => handleCopyEvidence(selectedNode.evidenceId!)}
                      className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                    >
                      {copiedEvidenceId === selectedNode.evidenceId ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  )}
                </div>
              </div>

              <div className="space-y-1">
                <p className="text-[10px] font-bold text-slate-400 uppercase">Detection Engine</p>
                <p className="font-mono text-slate-200 bg-slate-950 p-2 rounded border border-slate-800 truncate">
                  {selectedNode.sourceEngine || 'DeceptiScope Multi-Engine'}
                </p>
              </div>

              {selectedNode.confidence != null && (
                <div className="space-y-1">
                  <div className="flex justify-between text-[10px] font-mono">
                    <span className="text-slate-400 uppercase">Confidence</span>
                    <span className="font-bold text-emerald-400">
                      {(selectedNode.confidence * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                    <div
                      className="h-full bg-emerald-500 rounded-full"
                      style={{ width: `${selectedNode.confidence * 100}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
