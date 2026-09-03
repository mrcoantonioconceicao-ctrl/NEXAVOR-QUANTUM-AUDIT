import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Network,
  Database,
  Cpu,
  Layers,
  Search,
  Sparkles,
  ShieldAlert,
  Sliders,
  FileCode2,
  Key,
  Box,
  FileText,
  Download,
  Copy,
  Check,
  ArrowRight,
  Zap,
  Terminal,
  Activity,
  GitCommit,
  CheckCircle2,
  RefreshCw,
  Filter,
  X,
  AlertTriangle,
  Camera,
  Bookmark,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Trash2,
  Clock,
  FolderOpen,
  Save,
  Maximize2,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';
import { GraphSyncService } from '../domain/knowledgeGraph/GraphSyncService.ts';
import { hybridRagService } from '../domain/knowledgeGraph/HybridRAGService.ts';
import { CypherOntology } from '../domain/knowledgeGraph/CypherOntology.ts';
import {
  SecurityKnowledgeGraph,
  GraphNode,
  MultiHopImpactTree,
  HybridRAGQueryResult,
} from '../domain/knowledgeGraph/types.ts';

export interface GraphSnapshot {
  id: string;
  name: string;
  timestamp: string;
  zoomLevel: number;
  selectedLabelFilter: string;
  selectedRiskFilter: string;
  searchQuery: string;
  selectedNodeId: string | null;
  activeTab: 'canvas' | 'impact' | 'rag' | 'cypher';
  impactTargetId: string;
  impactMaxDepth: number;
  ragQuery: string;
  vectorWeight: number;
  graphWeight: number;
  nodeCount: number;
}

interface GraphRagVisualizerProps {
  report: SecurityAuditReport | null;
  showNotification?: (msg: string) => void;
}

export const GraphRagVisualizer: React.FC<GraphRagVisualizerProps> = ({ report, showNotification }) => {
  const [graphData, setGraphData] = useState<SecurityKnowledgeGraph>(() =>
    GraphSyncService.syncAuditReportToGraph(report)
  );
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [activeTab, setActiveTab] = useState<'canvas' | 'impact' | 'rag' | 'cypher'>('canvas');

  // Entity Type & Severity Quick Filters State
  const [selectedLabelFilter, setSelectedLabelFilter] = useState<string>('ALL');
  const [selectedRiskFilter, setSelectedRiskFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Contagem por Tipo de Entidade (para os Badges dos Filtros)
  const labelCounts = useMemo(() => {
    const counts: Record<string, number> = {
      ALL: graphData.nodes.length,
      ComplianceRule: 0,
      Vulnerability: 0,
      CodeFile: 0,
      ASTFunction: 0,
      CryptoAlgorithm: 0,
      SBOMPackage: 0,
    };
    graphData.nodes.forEach((node) => {
      if (counts[node.label] !== undefined) {
        counts[node.label]++;
      } else {
        counts[node.label] = 1;
      }
    });
    return counts;
  }, [graphData.nodes]);

  // Nós Filtrados com base nas escolhas do Auditor
  const filteredNodes = useMemo(() => {
    return graphData.nodes.filter((node) => {
      if (selectedLabelFilter !== 'ALL' && node.label !== selectedLabelFilter) {
        return false;
      }
      if (selectedRiskFilter !== 'ALL' && node.riskLevel !== selectedRiskFilter) {
        return false;
      }
      if (searchQuery.trim() !== '') {
        const q = searchQuery.toLowerCase();
        const nameMatch = node.name.toLowerCase().includes(q);
        const idMatch = node.id.toLowerCase().includes(q);
        const propsMatch = Object.values(node.properties || {}).some((val) =>
          String(val).toLowerCase().includes(q)
        );
        if (!nameMatch && !idMatch && !propsMatch) {
          return false;
        }
      }
      return true;
    });
  }, [graphData.nodes, selectedLabelFilter, selectedRiskFilter, searchQuery]);

  // Manter selectedNode válido quando os filtros forem alterados
  useEffect(() => {
    if (filteredNodes.length > 0) {
      if (!selectedNode || !filteredNodes.some((n) => n.id === selectedNode.id)) {
        setSelectedNode(filteredNodes[0]);
      }
    } else {
      setSelectedNode(null);
    }
  }, [filteredNodes]);

  // Multi-Hop Impact Sandbox State
  const [impactTargetId, setImpactTargetId] = useState<string>(
    'programs/solana_sandbox_counter/src/lib.rs'
  );
  const [impactMaxDepth, setImpactMaxDepth] = useState<number>(3);
  const [impactTree, setImpactTree] = useState<MultiHopImpactTree>(() =>
    GraphSyncService.queryImpactTree('programs/solana_sandbox_counter/src/lib.rs', 3)
  );

  // Hybrid RAG Query State
  const [ragQuery, setRagQuery] = useState<string>(
    'Como mitigar o risco de integer overflow no smart contract e garantir conformidade FIPS 204?'
  );
  const [vectorWeight, setVectorWeight] = useState<number>(0.5);
  const [graphWeight, setGraphWeight] = useState<number>(0.5);
  const [isExecutingRag, setIsExecutingRag] = useState<boolean>(false);
  const [ragResult, setRagResult] = useState<HybridRAGQueryResult | null>(null);

  // Cypher Copy State
  const [copiedCypher, setCopiedCypher] = useState<boolean>(false);

  // Zoom Level State (0.6x a 1.6x)
  const [zoomLevel, setZoomLevel] = useState<number>(1.0);

  // Snapshots Persistence State (localStorage)
  const [snapshots, setSnapshots] = useState<GraphSnapshot[]>(() => {
    try {
      const saved = localStorage.getItem('nexavor_graph_snapshots');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  const [isSnapshotModalOpen, setIsSnapshotModalOpen] = useState<boolean>(false);
  const [isCreatingSnapshot, setIsCreatingSnapshot] = useState<boolean>(false);
  const [snapshotNameInput, setSnapshotNameInput] = useState<string>('');

  // Persistir snapshots no localStorage
  useEffect(() => {
    try {
      localStorage.setItem('nexavor_graph_snapshots', JSON.stringify(snapshots));
    } catch (err) {
      console.error('Erro ao salvar snapshots no localStorage:', err);
    }
  }, [snapshots]);

  // Handler para Criar/Salvar Snapshot
  const handleCreateSnapshot = (customName?: string) => {
    const finalName =
      (customName && customName.trim()) ||
      `Snapshot ${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })} (${
        selectedLabelFilter !== 'ALL' ? selectedLabelFilter : 'Todos'
      })`;

    const newSnap: GraphSnapshot = {
      id: `snap_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
      name: finalName,
      timestamp: new Date().toLocaleString('pt-BR'),
      zoomLevel,
      selectedLabelFilter,
      selectedRiskFilter,
      searchQuery,
      selectedNodeId: selectedNode?.id || null,
      activeTab,
      impactTargetId,
      impactMaxDepth,
      ragQuery,
      vectorWeight,
      graphWeight,
      nodeCount: filteredNodes.length,
    };

    setSnapshots((prev) => [newSnap, ...prev]);
    setIsCreatingSnapshot(false);
    setSnapshotNameInput('');

    const notifyMsg = `📸 Snapshot "${finalName}" salvo! (${filteredNodes.length} nós | Zoom: ${(
      zoomLevel * 100
    ).toFixed(0)}%)`;
    if (showNotification) {
      showNotification(notifyMsg);
    }
  };

  // Handler para Restaurar Estado a partir de um Snapshot
  const handleRestoreSnapshot = (snap: GraphSnapshot) => {
    setZoomLevel(snap.zoomLevel || 1.0);
    setSelectedLabelFilter(snap.selectedLabelFilter || 'ALL');
    setSelectedRiskFilter(snap.selectedRiskFilter || 'ALL');
    setSearchQuery(snap.searchQuery || '');
    setActiveTab(snap.activeTab || 'canvas');
    if (snap.impactTargetId) setImpactTargetId(snap.impactTargetId);
    if (snap.impactMaxDepth) setImpactMaxDepth(snap.impactMaxDepth);
    if (snap.ragQuery) setRagQuery(snap.ragQuery);
    if (snap.vectorWeight !== undefined) setVectorWeight(snap.vectorWeight);
    if (snap.graphWeight !== undefined) setGraphWeight(snap.graphWeight);

    if (snap.selectedNodeId) {
      const found = graphData.nodes.find((n) => n.id === snap.selectedNodeId);
      if (found) {
        setSelectedNode(found);
      }
    }

    setIsSnapshotModalOpen(false);

    const restoreMsg = `🔄 Estado do grafo restaurado: "${snap.name}" (Zoom: ${(
      (snap.zoomLevel || 1) * 100
    ).toFixed(0)}%)`;
    if (showNotification) {
      showNotification(restoreMsg);
    }
  };

  // Handler para Deletar Snapshot
  const handleDeleteSnapshot = (id: string, name: string) => {
    setSnapshots((prev) => prev.filter((s) => s.id !== id));
    if (showNotification) {
      showNotification(`🗑️ Snapshot "${name}" removido.`);
    }
  };

  // Exportar Snapshots em formato JSON
  const handleExportSnapshots = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(snapshots, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `nexavor_graph_snapshots_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  useEffect(() => {
    const updated = GraphSyncService.syncAuditReportToGraph(report);
    setGraphData(updated);
    if (updated.nodes.length > 0) {
      setSelectedNode(updated.nodes[0]);
    }
  }, [report]);

  // Handler para Análise de Impacto
  const handleCalculateImpact = () => {
    const tree = GraphSyncService.queryImpactTree(impactTargetId, impactMaxDepth);
    setImpactTree(tree);
  };

  // Handler para RAG Híbrido
  const handleRunHybridRag = async () => {
    setIsExecutingRag(true);
    try {
      const res = await hybridRagService.executeHybridQuery(
        {
          query: ragQuery,
          targetFileOrFunction: impactTargetId,
          vectorWeight,
          graphWeight,
          topK: 5,
        },
        showNotification
      );
      setRagResult(res);
    } catch (err) {
      console.error('Erro ao executar RAG Híbrido:', err);
    } finally {
      setIsExecutingRag(false);
    }
  };

  // Handler para Copiar Cypher
  const handleCopyCypher = () => {
    const script = CypherOntology.generateCypherBatchImport(graphData.nodes, graphData.relationships);
    navigator.clipboard.writeText(script);
    setCopiedCypher(true);
    setTimeout(() => setCopiedCypher(false), 2000);
  };

  // Helper de Cores para Rótulos de Nós
  const getNodeBadgeColor = (label: string) => {
    switch (label) {
      case 'CodeFile':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'ASTFunction':
        return 'bg-purple-500/10 text-purple-300 border-purple-500/30';
      case 'CryptoAlgorithm':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'Vulnerability':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'ComplianceRule':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'SBOMPackage':
        return 'bg-teal-500/10 text-teal-400 border-teal-500/30';
      default:
        return 'bg-zinc-800 text-zinc-300 border-zinc-700';
    }
  };

  const getNodeIcon = (label: string) => {
    switch (label) {
      case 'CodeFile':
        return <FileCode2 className="w-4 h-4 text-blue-400" />;
      case 'ASTFunction':
        return <Cpu className="w-4 h-4 text-purple-400" />;
      case 'CryptoAlgorithm':
        return <Key className="w-4 h-4 text-amber-400" />;
      case 'Vulnerability':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      case 'ComplianceRule':
        return <FileText className="w-4 h-4 text-emerald-400" />;
      case 'SBOMPackage':
        return <Box className="w-4 h-4 text-teal-400" />;
      default:
        return <Layers className="w-4 h-4 text-zinc-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner / Header */}
      <div className="bg-gradient-to-r from-purple-950/40 via-zinc-900 to-indigo-950/40 border border-purple-500/30 rounded-xl p-6 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <Network className="w-64 h-64 text-purple-400" />
        </div>
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <span className="px-3 py-1 bg-purple-500/20 text-purple-300 border border-purple-500/40 text-xs font-semibold rounded-full flex items-center space-x-1.5">
                <Network className="w-3.5 h-3.5 text-purple-400" />
                <span>NEXAVOR GRAPH RAG ENGINE v2.1</span>
              </span>
              <span className="px-2.5 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] font-mono rounded">
                Neo4j / FalkorDB / Memgraph Ready
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              Grafo de Conhecimento de Segurança & RAG Híbrido
            </h1>
            <p className="text-sm text-zinc-400 max-w-3xl mt-1 leading-relaxed">
              Orquestração de <strong className="text-zinc-200">Vector RAG</strong> (passagens normativas NIST/FIPS/PCI-DSS) + <strong className="text-purple-300">GraphRAG</strong> (navegação multi-hop de AST, supply chain e conformidade relacional) para consultas zeradas de alucinação no Gemini Engine.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                setSnapshotNameInput(
                  `Snap: ${selectedLabelFilter !== 'ALL' ? selectedLabelFilter : 'Geral'} (${filteredNodes.length} nós) - ${new Date().toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })}`
                );
                setIsCreatingSnapshot(true);
              }}
              className="px-3.5 py-2 bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 text-xs font-semibold rounded-lg border border-amber-500/30 transition-all flex items-center space-x-1.5 shadow-sm"
              title="Salvar instantaneamente o estado atual do grafo (zoom, filtros e seleção)"
            >
              <Camera className="w-4 h-4 text-amber-400" />
              <span>Salvar Snapshot</span>
            </button>

            <button
              onClick={() => setIsSnapshotModalOpen(true)}
              className="px-3.5 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium rounded-lg border border-zinc-700 transition-all flex items-center space-x-1.5"
            >
              <Bookmark className="w-4 h-4 text-purple-400" />
              <span>Snapshots</span>
              {snapshots.length > 0 && (
                <span className="px-1.5 py-0.2 text-[10px] font-mono font-bold bg-purple-500 text-white rounded-full ml-1">
                  {snapshots.length}
                </span>
              )}
            </button>

            <button
              onClick={handleCopyCypher}
              className="px-3.5 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium rounded-lg border border-zinc-700 transition-all flex items-center space-x-2"
            >
              {copiedCypher ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4 text-zinc-400" />}
              <span>{copiedCypher ? 'Cypher Copiado!' : 'Copiar Cypher DDL'}</span>
            </button>

            <button
              onClick={() => setGraphData(GraphSyncService.syncAuditReportToGraph(report))}
              className="px-3.5 py-2 bg-purple-600 hover:bg-purple-500 text-white text-xs font-medium rounded-lg shadow-lg shadow-purple-600/20 transition-all flex items-center space-x-2"
            >
              <RefreshCw className="w-4 h-4" />
              <span>Sincronizar Grafo</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center space-x-2 mt-6 pt-4 border-t border-zinc-800">
          <button
            onClick={() => setActiveTab('canvas')}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center space-x-2 ${
              activeTab === 'canvas'
                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <Network className="w-4 h-4" />
            <span>Visualizador de Grafo ({graphData.nodes.length} Nós)</span>
          </button>

          <button
            onClick={() => setActiveTab('impact')}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center space-x-2 ${
              activeTab === 'impact'
                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <Zap className="w-4 h-4" />
            <span>Análise de Impacto Multi-Hop</span>
          </button>

          <button
            onClick={() => setActiveTab('rag')}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center space-x-2 ${
              activeTab === 'rag'
                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <Sparkles className="w-4 h-4 text-purple-400" />
            <span>Workbench RAG Híbrido (Vector + Graph)</span>
          </button>

          <button
            onClick={() => setActiveTab('cypher')}
            className={`px-4 py-2 text-xs font-medium rounded-lg transition-all flex items-center space-x-2 ${
              activeTab === 'cypher'
                ? 'bg-purple-600/30 text-purple-300 border border-purple-500/50 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/60'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>Ontologia Cypher / DDL</span>
          </button>
        </div>
      </div>

      {/* TAB 1: VISUALIZADOR DE GRAFO */}
      {activeTab === 'canvas' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Graph Grid / Canvas */}
          <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col h-[620px]">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center space-x-2">
                <Network className="w-5 h-5 text-purple-400" />
                <h3 className="text-sm font-semibold text-zinc-100">Mapa de Ontologia de Segurança</h3>
              </div>
              <span className="text-xs font-mono text-zinc-400">
                Exibindo <strong className="text-purple-300 font-bold">{filteredNodes.length}</strong> de {graphData.nodes.length} Nós | {graphData.relationships.length} Arestas
              </span>
            </div>

            {/* Quick Entity Type & Search Toolbar */}
            <div className="py-3 border-b border-zinc-800/80 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                {/* Search Input */}
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Filtrar por nome, ID ou propriedade..."
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-purple-500/80 rounded-lg pl-8 pr-7 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 outline-none transition-all font-mono"
                  />
                  {searchQuery && (
                    <button
                      onClick={() => setSearchQuery('')}
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
                    >
                      <X className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                {/* Risk Level Filter */}
                <div className="flex items-center space-x-1.5">
                  <Filter className="w-3.5 h-3.5 text-zinc-400" />
                  <select
                    value={selectedRiskFilter}
                    onChange={(e) => setSelectedRiskFilter(e.target.value)}
                    className="bg-zinc-950 border border-zinc-800 focus:border-purple-500 rounded-lg px-2.5 py-1.5 text-xs text-zinc-200 outline-none font-mono"
                  >
                    <option value="ALL">Todas Severidades</option>
                    <option value="CRITICAL">🔴 CRITICAL</option>
                    <option value="HIGH">🟠 HIGH</option>
                    <option value="MEDIUM">🟡 MEDIUM</option>
                    <option value="LOW">🔵 LOW</option>
                    <option value="SAFE">🟢 SAFE</option>
                  </select>
                </div>

                {/* Clear Filters Button */}
                {(selectedLabelFilter !== 'ALL' || selectedRiskFilter !== 'ALL' || searchQuery) && (
                  <button
                    onClick={() => {
                      setSelectedLabelFilter('ALL');
                      setSelectedRiskFilter('ALL');
                      setSearchQuery('');
                    }}
                    className="px-2.5 py-1.5 bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 border border-rose-500/30 rounded-lg text-xs font-mono transition-all flex items-center space-x-1"
                  >
                    <X className="w-3.5 h-3.5" />
                    <span>Limpar Filtros</span>
                  </button>
                )}
              </div>

              {/* Entity Type Filter Badges Row */}
              <div className="flex items-center space-x-1.5 overflow-x-auto pb-1 custom-scrollbar text-xs font-mono">
                <span className="text-[11px] text-zinc-500 font-semibold mr-1 shrink-0 flex items-center gap-1">
                  <Filter className="w-3 h-3 text-purple-400" />
                  Entidade:
                </span>

                <button
                  onClick={() => setSelectedLabelFilter('ALL')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'ALL'
                      ? 'bg-purple-600/30 border-purple-500 text-purple-200 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:border-zinc-700'
                  }`}
                >
                  <Layers className="w-3 h-3" />
                  <span>Todos ({labelCounts.ALL})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('ComplianceRule')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'ComplianceRule'
                      ? 'bg-emerald-500/20 border-emerald-500 text-emerald-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-emerald-400/80 hover:text-emerald-300 hover:border-emerald-500/50'
                  }`}
                >
                  <FileText className="w-3 h-3" />
                  <span>ComplianceRule ({labelCounts.ComplianceRule})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('Vulnerability')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'Vulnerability'
                      ? 'bg-rose-500/20 border-rose-500 text-rose-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-rose-400/80 hover:text-rose-300 hover:border-rose-500/50'
                  }`}
                >
                  <ShieldAlert className="w-3 h-3" />
                  <span>Vulnerability ({labelCounts.Vulnerability})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('CodeFile')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'CodeFile'
                      ? 'bg-blue-500/20 border-blue-500 text-blue-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-blue-400/80 hover:text-blue-300 hover:border-blue-500/50'
                  }`}
                >
                  <FileCode2 className="w-3 h-3" />
                  <span>CodeFile ({labelCounts.CodeFile})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('ASTFunction')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'ASTFunction'
                      ? 'bg-purple-500/20 border-purple-500 text-purple-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-purple-400/80 hover:text-purple-300 hover:border-purple-500/50'
                  }`}
                >
                  <Cpu className="w-3 h-3" />
                  <span>ASTFunction ({labelCounts.ASTFunction})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('CryptoAlgorithm')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'CryptoAlgorithm'
                      ? 'bg-amber-500/20 border-amber-500 text-amber-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-amber-400/80 hover:text-amber-300 hover:border-amber-500/50'
                  }`}
                >
                  <Key className="w-3 h-3" />
                  <span>CryptoAlgorithm ({labelCounts.CryptoAlgorithm})</span>
                </button>

                <button
                  onClick={() => setSelectedLabelFilter('SBOMPackage')}
                  className={`px-2.5 py-1 rounded-md border text-[11px] shrink-0 transition-all flex items-center space-x-1 ${
                    selectedLabelFilter === 'SBOMPackage'
                      ? 'bg-teal-500/20 border-teal-500 text-teal-300 font-semibold shadow-sm'
                      : 'bg-zinc-950 border-zinc-800 text-teal-400/80 hover:text-teal-300 hover:border-teal-500/50'
                  }`}
                >
                  <Box className="w-3 h-3" />
                  <span>SBOMPackage ({labelCounts.SBOMPackage})</span>
                </button>
              </div>
            </div>

            {/* Visual Node Grid Representation */}
            <div className="flex-1 my-3 bg-zinc-950 rounded-lg border border-zinc-800 p-4 overflow-y-auto space-y-3 relative custom-scrollbar">
              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-zinc-500 uppercase tracking-wider mb-2 pb-2 border-b border-zinc-900">
                <span>Entidades Filtradas no Grafo ({filteredNodes.length})</span>

                {/* Controles de Zoom da Visualização */}
                <div className="flex items-center space-x-1 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
                  <button
                    onClick={() => setZoomLevel((prev) => Math.max(0.6, Math.round((prev - 0.1) * 10) / 10))}
                    disabled={zoomLevel <= 0.6}
                    title="Diminuir Zoom"
                    className="p-1 hover:bg-zinc-800 rounded text-zinc-400 hover:text-zinc-200 disabled:opacity-40 transition-all"
                  >
                    <ZoomOut className="w-3.5 h-3.5" />
                  </button>
                  <span className="text-[10px] font-mono text-purple-300 font-semibold px-1.5 min-w-[38px] text-center">
                    {Math.round(zoomLevel * 100)}%
                  </span>
                  <button
                    onClick={() => setZoomLevel((prev) => Math.min(1.6, Math.round((prev + 0.1) * 10) / 10))}
                    disabled={zoomLevel >= 1.6}
                    title="Aumentar Zoom"
                    className="p-1 hover:bg-zinc-800 rounded text-zinc-400 hover:text-zinc-200 disabled:opacity-40 transition-all"
                  >
                    <ZoomIn className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setZoomLevel(1.0)}
                    title="Resetar Zoom (100%)"
                    className="p-1 hover:bg-zinc-800 rounded text-zinc-500 hover:text-zinc-300 transition-all ml-1 border-l border-zinc-800 pl-1.5"
                  >
                    <RotateCcw className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {filteredNodes.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-500 space-y-2 my-8">
                  <AlertTriangle className="w-8 h-8 text-amber-400" />
                  <p className="text-xs font-semibold text-zinc-300">Nenhuma entidade encontrada para os filtros aplicados.</p>
                  <button
                    onClick={() => {
                      setSelectedLabelFilter('ALL');
                      setSelectedRiskFilter('ALL');
                      setSearchQuery('');
                    }}
                    className="text-xs text-purple-400 hover:underline font-mono"
                  >
                    Redefinir Filtros
                  </button>
                </div>
              ) : (
                <div
                  className="grid grid-cols-1 sm:grid-cols-2 gap-3 transition-transform duration-200 origin-top-left"
                  style={{ transform: `scale(${zoomLevel})`, transformOrigin: 'top left' }}
                >
                  <AnimatePresence mode="popLayout">
                    {filteredNodes.map((node, index) => {
                      const isSelected = selectedNode?.id === node.id;
                      const isCriticalType = node.label === 'Vulnerability' || node.label === 'ComplianceRule';

                      return (
                        <motion.button
                          key={node.id}
                          layout
                          initial={{ opacity: 0, scale: 0.9, y: 12 }}
                          animate={{ opacity: 1, scale: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.9, y: -8 }}
                          transition={{
                            duration: isCriticalType ? 0.35 : 0.25,
                            delay: Math.min(index * 0.03, 0.3),
                            type: isCriticalType ? 'spring' : 'tween',
                            stiffness: 260,
                            damping: 20,
                          }}
                          onClick={() => setSelectedNode(node)}
                          className={`text-left p-3 rounded-lg border transition-all flex items-start justify-between space-x-3 relative overflow-hidden ${
                            isSelected
                              ? 'bg-purple-950/40 border-purple-500/60 shadow-lg ring-1 ring-purple-500/50'
                              : 'bg-zinc-900/80 border-zinc-800 hover:border-zinc-700 hover:bg-zinc-850'
                          } ${
                            node.label === 'Vulnerability'
                              ? 'hover:border-rose-500/50 hover:shadow-rose-500/10'
                              : node.label === 'ComplianceRule'
                              ? 'hover:border-emerald-500/50 hover:shadow-emerald-500/10'
                              : ''
                          }`}
                        >
                          {/* Entrada animada especial com brilho suave para Vulnerabilidade & ComplianceRule */}
                          {isCriticalType && (
                            <motion.div
                              initial={{ opacity: 0.6, scale: 0.95 }}
                              animate={{ opacity: [0.6, 0.15, 0], scale: [0.95, 1.05, 1.1] }}
                              transition={{ duration: 1.2, ease: 'easeOut' }}
                              className={`absolute inset-0 pointer-events-none rounded-lg ${
                                node.label === 'Vulnerability'
                                  ? 'bg-rose-500/20 ring-2 ring-rose-500/40'
                                  : 'bg-emerald-500/20 ring-2 ring-emerald-500/40'
                              }`}
                            />
                          )}

                          <div className="flex items-start space-x-3 relative z-10">
                            <div className="p-2 rounded-lg bg-zinc-950 border border-zinc-800 mt-0.5">
                              {getNodeIcon(node.label)}
                            </div>
                            <div>
                              <div className="flex items-center space-x-1.5 mb-1">
                                <span className={`inline-block px-2 py-0.5 text-[10px] font-mono rounded border ${getNodeBadgeColor(node.label)}`}>
                                  {node.label}
                                </span>
                                {isCriticalType && (
                                  <motion.span
                                    initial={{ scale: 0 }}
                                    animate={{ scale: 1 }}
                                    transition={{ delay: 0.2 }}
                                    className={`w-2 h-2 rounded-full ${
                                      node.label === 'Vulnerability' ? 'bg-rose-500 animate-pulse' : 'bg-emerald-400 animate-pulse'
                                    }`}
                                  />
                                )}
                              </div>
                              <h4 className="text-xs font-semibold text-zinc-200 line-clamp-1">{node.name}</h4>
                              <p className="text-[11px] font-mono text-zinc-400 mt-0.5">ID: {node.id}</p>
                            </div>
                          </div>

                          {node.riskLevel && (
                            <span
                              className={`px-1.5 py-0.5 text-[10px] font-bold font-mono rounded shrink-0 relative z-10 ${
                                node.riskLevel === 'CRITICAL'
                                  ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                                  : node.riskLevel === 'HIGH'
                                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                                  : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              }`}
                            >
                              {node.riskLevel}
                            </span>
                          )}
                        </motion.button>
                      );
                    })}
                  </AnimatePresence>
                </div>
              )}
            </div>

            {/* Graph Legend Footer */}
            <div className="pt-3 border-t border-zinc-800 flex items-center justify-between text-[11px] text-zinc-400 font-mono">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block"></span> CodeFile</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block"></span> ASTFunction</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block"></span> CryptoAlgorithm</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block"></span> Vulnerability</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block"></span> ComplianceRule</span>
            </div>
          </div>

          {/* Node Properties Inspector Side Panel */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-5 shadow-xl flex flex-col h-[620px]">
            <div className="pb-3 border-b border-zinc-800 flex items-center space-x-2">
              <Layers className="w-5 h-5 text-purple-400" />
              <h3 className="text-sm font-semibold text-zinc-100">Inspetor de Entidade & Relacionamentos</h3>
            </div>

            {selectedNode ? (
              <div className="my-4 space-y-4 flex-1 overflow-y-auto custom-scrollbar pr-1">
                <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800">
                  <div className="flex items-center justify-between mb-2">
                    <span className={`px-2.5 py-0.5 text-xs font-mono rounded border ${getNodeBadgeColor(selectedNode.label)}`}>
                      {selectedNode.label}
                    </span>
                    <span className="text-[11px] font-mono text-zinc-500">Node ID: {selectedNode.id}</span>
                  </div>
                  <h4 className="text-base font-bold text-white mb-1">{selectedNode.name}</h4>
                  {selectedNode.riskLevel && (
                    <div className="mt-2 flex items-center space-x-2">
                      <span className="text-xs text-zinc-400">Nível de Risco:</span>
                      <span className="px-2 py-0.5 text-xs font-bold font-mono rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                        {selectedNode.riskLevel}
                      </span>
                    </div>
                  )}
                </div>

                {/* Node Properties */}
                <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800 space-y-2">
                  <h5 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider font-mono">
                    Propriedades do Nó
                  </h5>
                  <div className="space-y-1 font-mono text-xs">
                    {Object.entries(selectedNode.properties || {}).map(([k, v]) => (
                      <div key={k} className="flex items-center justify-between py-1 border-b border-zinc-900 text-zinc-300">
                        <span className="text-zinc-500">{k}:</span>
                        <span className="text-purple-300 font-semibold">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Connected Relationships */}
                <div className="bg-zinc-950 p-4 rounded-lg border border-zinc-800 space-y-2">
                  <h5 className="text-xs font-semibold text-zinc-300 uppercase tracking-wider font-mono">
                    Arestas de Conexão no Grafo
                  </h5>
                  <div className="space-y-2 text-xs">
                    {graphData.relationships
                      .filter((r) => r.sourceId === selectedNode.id || r.targetId === selectedNode.id)
                      .map((rel) => {
                        const isOutgoing = rel.sourceId === selectedNode.id;
                        const otherNodeId = isOutgoing ? rel.targetId : rel.sourceId;
                        const otherNode = graphData.nodes.find((n) => n.id === otherNodeId);

                        return (
                          <div
                            key={rel.id}
                            className="p-2.5 rounded bg-zinc-900 border border-zinc-800 flex items-center justify-between font-mono"
                          >
                            <span className="text-purple-400 font-bold">:{rel.type}</span>
                            <div className="flex items-center space-x-1.5 text-zinc-300 text-[11px]">
                              <span>{isOutgoing ? '➔ Outgoing' : '⬅ Incoming'}</span>
                              <span className="text-zinc-500 font-bold">({otherNode?.name || otherNodeId})</span>
                            </div>
                          </div>
                        );
                      })}
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-zinc-500">
                <Network className="w-12 h-12 text-zinc-700 mb-2" />
                <p className="text-xs">Selecione um nó no painel da esquerda para inspecionar seus atributos e conexões no grafo.</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: ANÁLISE DE IMPACTO MULTI-HOP */}
      {activeTab === 'impact' && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Zap className="w-5 h-5 text-purple-400" />
                <span>Navegação de Impacto Multi-Hop no Grafo (GraphRAG)</span>
              </h3>
              <p className="text-xs text-zinc-400 mt-1">
                Selecione o nó de origem e a profundidade de salto (hops) para rastrear a propagação em cadeia de vulnerabilidades, chamadas AST e violações de conformidade.
              </p>
            </div>

            <div className="flex items-center space-x-3 w-full md:w-auto">
              <div className="flex items-center space-x-2">
                <label className="text-xs font-mono text-zinc-400">Origem:</label>
                <select
                  value={impactTargetId}
                  onChange={(e) => setImpactTargetId(e.target.value)}
                  className="bg-zinc-950 border border-zinc-700 focus:border-purple-500 rounded px-3 py-1.5 text-xs text-white outline-none font-mono"
                >
                  {graphData.nodes.map((n) => (
                    <option key={n.id} value={n.id}>
                      [{n.label}] {n.name}
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center space-x-2">
                <label className="text-xs font-mono text-zinc-400">Saltos (Hops):</label>
                <select
                  value={impactMaxDepth}
                  onChange={(e) => setImpactMaxDepth(Number(e.target.value))}
                  className="bg-zinc-950 border border-zinc-700 focus:border-purple-500 rounded px-2.5 py-1.5 text-xs text-white outline-none font-mono"
                >
                  <option value={1}>1 Salto</option>
                  <option value={2}>2 Saltos</option>
                  <option value={3}>3 Saltos</option>
                  <option value={4}>4 Saltos</option>
                  <option value={5}>5 Saltos</option>
                </select>
              </div>

              <button
                onClick={handleCalculateImpact}
                className="px-4 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded shadow-md transition-all flex items-center space-x-1.5"
              >
                <Search className="w-3.5 h-3.5" />
                <span>Analisar Impacto</span>
              </button>
            </div>
          </div>

          {/* Impact Overview Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
            <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800">
              <span className="text-xs font-mono text-zinc-400">Nós Encadeados Afetados</span>
              <p className="text-2xl font-extrabold text-purple-300 mt-1">{impactTree.impactedNodes.length}</p>
            </div>
            <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800">
              <span className="text-xs font-mono text-zinc-400">Funções AST Afetadas</span>
              <p className="text-2xl font-extrabold text-blue-400 mt-1">{impactTree.totalAffectedFunctions}</p>
            </div>
            <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800">
              <span className="text-xs font-mono text-zinc-400">Vulnerabilidades em Cadeia</span>
              <p className="text-2xl font-extrabold text-rose-400 mt-1">{impactTree.totalVulnerabilitiesCount}</p>
            </div>
            <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800">
              <span className="text-xs font-mono text-zinc-400">Violações de Normas</span>
              <p className="text-2xl font-extrabold text-emerald-400 mt-1">{impactTree.nonComplianceRulesViolated.length}</p>
            </div>
          </div>

          {/* Impact Tree List */}
          <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-3">
            <h4 className="text-xs font-semibold text-zinc-300 font-mono uppercase tracking-wider">
              Árvore de Impacto Relacional ({impactTree.rootNodeName})
            </h4>

            <div className="space-y-2 max-h-[360px] overflow-y-auto custom-scrollbar pr-2">
              {impactTree.impactedNodes.map((item, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-zinc-900 rounded-lg border border-zinc-800 flex items-start justify-between space-x-3 text-xs"
                >
                  <div className="flex items-start space-x-3">
                    <span className="px-2 py-1 bg-purple-950 border border-purple-500/40 text-purple-300 font-mono font-bold text-[11px] rounded">
                      Salto #{item.depth}
                    </span>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 text-[10px] font-mono rounded border ${getNodeBadgeColor(item.node.label)}`}>
                          {item.node.label}
                        </span>
                        <h5 className="font-bold text-white">{item.node.name}</h5>
                      </div>
                      <p className="text-zinc-400 mt-1 text-[11px] font-mono">{item.description}</p>
                    </div>
                  </div>

                  <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">
                    :{item.relationshipToParent}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: WORKBENCH RAG HÍBRIDO */}
      {activeTab === 'rag' && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-6">
          <div className="pb-4 border-b border-zinc-800 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-purple-400" />
                <span>Workbench de Fusão RAG Híbrida (Vector + GraphRAG)</span>
              </h3>
              <p className="text-xs text-zinc-400 mt-1">
                Combine a busca semântica em normas técnicas com o raciocínio relacional do Grafo de Conhecimento para alimentar a IA Generativa Gemini.
              </p>
            </div>

            <button
              onClick={handleRunHybridRag}
              disabled={isExecutingRag}
              className="px-5 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-purple-600/30 transition-all flex items-center space-x-2 disabled:opacity-50"
            >
              {isExecutingRag ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4 text-amber-300" />}
              <span>{isExecutingRag ? 'Executando RAG Híbrido...' : 'Executar Fusão RAG Híbrida'}</span>
            </button>
          </div>

          {/* Query Input & Sliders */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-3">
              <label className="text-xs font-mono text-zinc-300">Prompt / Consulta de Auditoria Semântica:</label>
              <textarea
                value={ragQuery}
                onChange={(e) => setRagQuery(e.target.value)}
                rows={3}
                className="w-full bg-zinc-950 border border-zinc-700 focus:border-purple-500 rounded-lg p-3 text-xs text-white outline-none font-mono resize-none shadow-inner"
                placeholder="Ex: Como mitigar o risco de integer overflow e implementar ML-DSA (FIPS 204) no smart contract Solana?"
              />
            </div>

            <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-zinc-300 flex items-center gap-1.5">
                  <Sliders className="w-3.5 h-3.5 text-purple-400" /> Ponderação Reranker (Weights)
                </span>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[11px] font-mono text-zinc-400">
                  <span>Vector RAG (Semântico):</span>
                  <span className="text-purple-300 font-bold">{Math.round(vectorWeight * 100)}%</span>
                </div>
                <input
                  type="range"
                  min={0.1}
                  max={1.0}
                  step={0.1}
                  value={vectorWeight}
                  onChange={(e) => {
                    const v = Number(e.target.value);
                    setVectorWeight(v);
                    setGraphWeight(Number((1 - v).toFixed(1)));
                  }}
                  className="w-full accent-purple-500"
                />
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-[11px] font-mono text-zinc-400">
                  <span>GraphRAG (Relacional):</span>
                  <span className="text-indigo-300 font-bold">{Math.round(graphWeight * 100)}%</span>
                </div>
                <input
                  type="range"
                  min={0.1}
                  max={1.0}
                  step={0.1}
                  value={graphWeight}
                  onChange={(e) => {
                    const g = Number(e.target.value);
                    setGraphWeight(g);
                    setVectorWeight(Number((1 - g).toFixed(1)));
                  }}
                  className="w-full accent-indigo-500"
                />
              </div>
            </div>
          </div>

          {/* RAG Results Display */}
          <AnimatePresence>
            {ragResult && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                transition={{ duration: 0.4, ease: 'easeOut' }}
                className="space-y-6 pt-4 border-t border-zinc-800"
              >
                {/* Telemetry Metrics Bar */}
                <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 flex flex-wrap items-center justify-between text-xs font-mono text-zinc-400">
                  <span className="flex items-center gap-1">
                    <Activity className="w-3.5 h-3.5 text-purple-400" /> Latência Total: <strong className="text-purple-300">{ragResult.metrics.totalMs}ms</strong>
                  </span>
                  <span>Vector Retrieval: <strong className="text-blue-400">{ragResult.metrics.vectorRetrievalMs}ms</strong></span>
                  <span>Graph Traversal: <strong className="text-emerald-400">{ragResult.metrics.graphRetrievalMs}ms</strong></span>
                  <span>Fusion & Rerank: <strong className="text-amber-400">{ragResult.metrics.fusionMs}ms</strong></span>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  {/* Vector Path Column */}
                  <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-3">
                    <h4 className="text-xs font-semibold text-blue-400 font-mono uppercase tracking-wider flex items-center gap-2">
                      <FileText className="w-4 h-4" /> Vector RAG (Trechos Normativos Recuperados)
                    </h4>
                    <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar pr-1">
                      {ragResult.vectorResults.map((v, i) => (
                        <motion.div
                          key={v.id}
                          initial={{ opacity: 0, x: -12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.25, delay: i * 0.08 }}
                          className="p-3 bg-zinc-900 rounded border border-zinc-800 space-y-1 hover:border-blue-500/40 transition-colors"
                        >
                          <div className="flex items-center justify-between text-xs font-bold text-white">
                            <span>{v.title}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">
                              Score: {v.similarityScore}
                            </span>
                          </div>
                          <p className="text-[11px] text-zinc-400 leading-relaxed">{v.content}</p>
                        </motion.div>
                      ))}
                    </div>
                  </div>

                  {/* GraphRAG Path Column */}
                  <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-3">
                    <h4 className="text-xs font-semibold text-emerald-400 font-mono uppercase tracking-wider flex items-center gap-2">
                      <Network className="w-4 h-4" /> GraphRAG (Subgrafo Relacional Extraído)
                    </h4>
                    <div className="space-y-2 max-h-[300px] overflow-y-auto custom-scrollbar pr-1 font-mono text-xs">
                      <div className="p-2.5 bg-zinc-900 rounded border border-zinc-800 text-[11px] text-purple-300">
                        <strong>Cypher Match Query:</strong>
                        <pre className="mt-1 text-[10px] text-zinc-400 overflow-x-auto">{ragResult.graphResult.cypherMatchQuery}</pre>
                      </div>

                      {ragResult.graphResult.relationshipPathSummary.map((path, i) => (
                        <motion.div
                          key={i}
                          initial={{ opacity: 0, x: 12 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{ duration: 0.25, delay: i * 0.08 }}
                          className="p-2.5 bg-zinc-900 rounded border border-zinc-800 text-[11px] text-zinc-300 hover:border-emerald-500/40 transition-colors"
                        >
                          {path}
                        </motion.div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Fused Context Prompt Output */}
                <motion.div
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3, delay: 0.2 }}
                  className="bg-zinc-950 p-4 rounded-xl border border-purple-500/40 space-y-2 font-mono shadow-lg shadow-purple-950/20"
                >
                  <h4 className="text-xs font-semibold text-purple-300 uppercase tracking-wider flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-purple-400" /> Prompt Contextual Enriquecido Gerado para o Gemini Engine
                  </h4>
                  <textarea
                    readOnly
                    value={ragResult.contextPrompt}
                    rows={8}
                    className="w-full bg-zinc-900 border border-zinc-800 rounded p-3 text-[11px] text-zinc-300 outline-none resize-none font-mono"
                  />
                </motion.div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      )}

      {/* TAB 4: ONTOLOGIA CYPHER & DDL */}
      {activeTab === 'cypher' && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-xl p-6 shadow-xl space-y-4 font-mono">
          <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
            <div>
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-purple-400" />
                <span>Script Cypher de Povoamento e Ontologia DDL</span>
              </h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Utilize o script abaixo para inicializar a ontologia do Grafo em instâncias do Neo4j, FalkorDB ou Memgraph.
              </p>
            </div>

            <button
              onClick={handleCopyCypher}
              className="px-3.5 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded shadow transition-all flex items-center space-x-1.5"
            >
              {copiedCypher ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCypher ? 'Copiado!' : 'Copiar Script Cypher'}</span>
            </button>
          </div>

          <pre className="bg-zinc-950 border border-zinc-800 rounded-lg p-4 text-xs text-purple-300 overflow-x-auto max-h-[480px] custom-scrollbar leading-relaxed">
            {CypherOntology.generateCypherBatchImport(graphData.nodes, graphData.relationships)}
          </pre>
        </div>
      )}

      {/* MODAL 1: CRIAR NOVO SNAPSHOT */}
      <AnimatePresence>
        {isCreatingSnapshot && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ duration: 0.2 }}
              className="bg-zinc-900 border border-amber-500/40 rounded-xl p-6 max-w-md w-full shadow-2xl space-y-4"
            >
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
                <div className="flex items-center space-x-2">
                  <Camera className="w-5 h-5 text-amber-400" />
                  <h3 className="text-base font-bold text-white">Salvar Snapshot de Análise</h3>
                </div>
                <button
                  onClick={() => setIsCreatingSnapshot(false)}
                  className="text-zinc-400 hover:text-white p-1 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-zinc-300 font-medium mb-1.5 font-mono">
                    Nome do Snapshot:
                  </label>
                  <input
                    type="text"
                    value={snapshotNameInput}
                    onChange={(e) => setSnapshotNameInput(e.target.value)}
                    placeholder="Ex: Auditoria NIST FIPS 204 - Módulo Solana"
                    className="w-full bg-zinc-950 border border-zinc-800 focus:border-amber-500 rounded-lg p-2.5 text-zinc-200 outline-none font-mono"
                    autoFocus
                  />
                </div>

                <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 space-y-1.5 font-mono text-[11px] text-zinc-400">
                  <span className="text-amber-400 font-semibold block mb-1">
                    📊 Estado a ser capturado:
                  </span>
                  <div className="flex justify-between">
                    <span>Nível de Zoom:</span>
                    <strong className="text-purple-300">{Math.round(zoomLevel * 100)}%</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Filtro de Tipo:</span>
                    <strong className="text-emerald-400">{selectedLabelFilter}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Filtro de Severidade:</span>
                    <strong className="text-rose-400">{selectedRiskFilter}</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Nós Visíveis:</span>
                    <strong className="text-zinc-200">{filteredNodes.length} de {graphData.nodes.length}</strong>
                  </div>
                  {selectedNode && (
                    <div className="flex justify-between">
                      <span>Nó Inspecionado:</span>
                      <strong className="text-blue-400 truncate max-w-[180px]">{selectedNode.name}</strong>
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-2 border-t border-zinc-800">
                <button
                  onClick={() => setIsCreatingSnapshot(false)}
                  className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium rounded-lg transition-all"
                >
                  Cancelar
                </button>
                <button
                  onClick={() => handleCreateSnapshot(snapshotNameInput)}
                  className="px-4 py-2 bg-gradient-to-r from-amber-600 to-amber-500 hover:from-amber-500 hover:to-amber-400 text-white text-xs font-semibold rounded-lg shadow-lg shadow-amber-600/20 transition-all flex items-center space-x-1.5"
                >
                  <Save className="w-4 h-4" />
                  <span>Confirmar & Salvar</span>
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

      {/* MODAL 2: GERENCIADOR DE SNAPSHOTS SALVOS */}
      <AnimatePresence>
        {isSnapshotModalOpen && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-md">
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 12 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 12 }}
              transition={{ duration: 0.25 }}
              className="bg-zinc-900 border border-purple-500/40 rounded-xl p-6 max-w-2xl w-full shadow-2xl space-y-4 max-h-[85vh] flex flex-col"
            >
              <div className="flex items-center justify-between pb-3 border-b border-zinc-800 shrink-0">
                <div className="flex items-center space-x-2">
                  <Bookmark className="w-5 h-5 text-purple-400" />
                  <h3 className="text-base font-bold text-white">
                    Histórico de Snapshots Salvos ({snapshots.length})
                  </h3>
                </div>
                <button
                  onClick={() => setIsSnapshotModalOpen(false)}
                  className="text-zinc-400 hover:text-white p-1 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Snapshots List */}
              <div className="flex-1 overflow-y-auto custom-scrollbar space-y-3 pr-1 py-1">
                {snapshots.length === 0 ? (
                  <div className="flex flex-col items-center justify-center p-12 text-center text-zinc-500 space-y-3">
                    <FolderOpen className="w-12 h-12 text-zinc-600" />
                    <div>
                      <p className="text-sm font-semibold text-zinc-300">Nenhum snapshot salvo ainda.</p>
                      <p className="text-xs text-zinc-500 mt-1 max-w-xs">
                        Utilize o botão "Salvar Snapshot" para gravar o estado de filtros, zoom e nós inspecionados para retornos futuros.
                      </p>
                    </div>
                  </div>
                ) : (
                  snapshots.map((snap) => (
                    <motion.div
                      key={snap.id}
                      initial={{ opacity: 0, y: 6 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-4 bg-zinc-950 border border-zinc-800 hover:border-purple-500/50 rounded-xl space-y-3 transition-all"
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div>
                          <h4 className="text-sm font-bold text-white flex items-center gap-2">
                            <span>{snap.name}</span>
                          </h4>
                          <span className="text-[11px] font-mono text-zinc-500 flex items-center gap-1 mt-0.5">
                            <Clock className="w-3 h-3 text-zinc-400" /> {snap.timestamp}
                          </span>
                        </div>

                        <div className="flex items-center space-x-2 shrink-0">
                          <button
                            onClick={() => handleRestoreSnapshot(snap)}
                            className="px-3 py-1.5 bg-purple-600/30 hover:bg-purple-600/50 text-purple-300 border border-purple-500/50 text-xs font-semibold rounded-lg transition-all flex items-center space-x-1"
                          >
                            <RotateCcw className="w-3.5 h-3.5" />
                            <span>Restaurar Estado</span>
                          </button>
                          <button
                            onClick={() => handleDeleteSnapshot(snap.id, snap.name)}
                            className="p-1.5 bg-zinc-900 hover:bg-rose-500/20 text-zinc-400 hover:text-rose-300 border border-zinc-800 hover:border-rose-500/30 rounded-lg transition-all"
                            title="Excluir Snapshot"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </div>

                      {/* Snapshot Metadata Chips */}
                      <div className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-purple-300">
                          Zoom: {Math.round((snap.zoomLevel || 1) * 100)}%
                        </span>
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-emerald-400">
                          Tipo: {snap.selectedLabelFilter}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-rose-400">
                          Severidade: {snap.selectedRiskFilter}
                        </span>
                        <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                          Nós: {snap.nodeCount || 0}
                        </span>
                        {snap.searchQuery && (
                          <span className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-amber-300 truncate max-w-[140px]">
                            Busca: "{snap.searchQuery}"
                          </span>
                        )}
                      </div>
                    </motion.div>
                  ))
                )}
              </div>

              <div className="flex items-center justify-between pt-3 border-t border-zinc-800 shrink-0">
                {snapshots.length > 0 ? (
                  <button
                    onClick={handleExportSnapshots}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono rounded-lg transition-all flex items-center space-x-1.5"
                  >
                    <Download className="w-3.5 h-3.5 text-purple-400" />
                    <span>Exportar Snapshots (JSON)</span>
                  </button>
                ) : <div />}

                <button
                  onClick={() => setIsSnapshotModalOpen(false)}
                  className="px-4 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-medium rounded-lg transition-all"
                >
                  Fechar
                </button>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </div>
  );
};
