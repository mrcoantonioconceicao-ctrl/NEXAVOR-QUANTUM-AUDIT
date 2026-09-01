import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Flame,
  Terminal,
  Activity,
  CheckCircle2,
  AlertOctagon,
  Copy,
  Check,
  Play,
  RotateCw,
  Search,
  Filter,
  Eye,
  FileCode2,
  Zap,
  Code2,
  Cpu,
  Layers,
  ArrowUpRight,
  Clock,
  GitBranch,
  GitCommit,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sliders,
  HelpCircle,
  Database,
  BarChart3,
  TrendingUp,
  Calendar,
  X,
  RefreshCw,
  AlertTriangle,
  FolderTree,
} from 'lucide-react';
import { FuzzCrashAlert } from '../domain/types.ts';
import { FuzzCrashAlertModal } from './FuzzCrashAlertModal.tsx';

export interface FuzzingRunRecord {
  id: string;
  target: 'ast_parser' | 'fuzz_structured_parser' | 'refactor_engine' | string;
  targetFile: string;
  timestamp: string;
  durationSeconds: number;
  totalExecutions: number;
  execSpeedPerSec: number;
  corpusCount: number;
  featuresDiscovered: number;
  branchCoveragePct: number;
  lineCoveragePct: number;
  edgeCoveragePct: number;
  status: 'PASSED' | 'CRASH_DETECTED' | 'TIMEOUT' | 'RUNNING';
  crashCount: number;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  commitSha: string;
  branch: string;
  author: string;
  sanitizer: 'AddressSanitizer (ASan)' | 'MemorySanitizer (MSan)' | 'UndefinedBehaviorSanitizer (UBSan)';
}

export interface FuzzCorpusItem {
  id: string;
  target: string;
  targetFile: string;
  sha256: string;
  sizeBytes: number;
  mutationType: string;
  hexPreview: string;
  asciiPreview: string;
  discoveredAt: string;
  triggeredCrash: boolean;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  crashIssueType?: string;
  coverageImpact: string;
}

export const PARSER_TARGET_FILE_MAP: Record<string, { file: string; targetFile: string; desc: string; type: string }> = {
  ast_parser: {
    file: 'crates/ast/src/parser.rs',
    targetFile: 'fuzz/fuzz_targets/ast_parser.rs',
    desc: 'Lexer e Parser Principal de Código Fonte Rust/TS (Buffer de Bytes Brutos)',
    type: 'Raw Bytes Fuzzer',
  },
  fuzz_structured_parser: {
    file: 'crates/ast/src/structured.rs',
    targetFile: 'fuzz/fuzz_targets/structured_parser.rs',
    desc: 'Parser Estruturado Tipado com Geração Arbitrária de AST (`arbitrary`)',
    type: 'Type-Guided Arbitrary AST',
  },
  refactor_engine: {
    file: 'crates/engine/src/refactor.rs',
    targetFile: 'fuzz/fuzz_targets/refactor_engine.rs',
    desc: 'Motor de Mutações, Patches e Reescrita de Árvore Sintática Segura',
    type: 'AST Patch Transformer',
  },
};

interface FuzzingDashboardProps {
  fuzzAlerts: FuzzCrashAlert[];
  onTriggerSimulateFuzz?: (target: string) => void;
  onNavigateToTests?: () => void;
  onNavigateToRefactor?: () => void;
  onResolveAlert?: (alertId: string) => void;
  showNotification: (msg: string) => void;
}

// Initial realistic benchmark history for Cargo-Fuzz LibFuzzer runs
const INITIAL_FUZZ_RUNS: FuzzingRunRecord[] = [
  {
    id: 'fuzz_run_2026_0901_01',
    target: 'ast_parser',
    targetFile: 'crates/ast/src/parser.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    durationSeconds: 120,
    totalExecutions: 3845920,
    execSpeedPerSec: 32049,
    corpusCount: 1420,
    featuresDiscovered: 4812,
    branchCoveragePct: 94.2,
    lineCoveragePct: 92.8,
    edgeCoveragePct: 96.1,
    status: 'CRASH_DETECTED',
    crashCount: 1,
    severity: 'CRITICAL',
    commitSha: 'e92f1b4',
    branch: 'main',
    author: 'mrcoantonioconceicao-ctrl',
    sanitizer: 'AddressSanitizer (ASan)',
  },
  {
    id: 'fuzz_run_2026_0901_02',
    target: 'fuzz_structured_parser',
    targetFile: 'crates/ast/src/structured.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 55).toISOString(),
    durationSeconds: 180,
    totalExecutions: 5920110,
    execSpeedPerSec: 32889,
    corpusCount: 2180,
    featuresDiscovered: 6390,
    branchCoveragePct: 97.4,
    lineCoveragePct: 95.1,
    edgeCoveragePct: 98.2,
    status: 'PASSED',
    crashCount: 0,
    commitSha: '7bc3901',
    branch: 'feat/pqc-refactor',
    author: 'sec-ci-automation',
    sanitizer: 'AddressSanitizer (ASan)',
  },
  {
    id: 'fuzz_run_2026_0901_03',
    target: 'refactor_engine',
    targetFile: 'crates/engine/src/refactor.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 140).toISOString(),
    durationSeconds: 150,
    totalExecutions: 4120800,
    execSpeedPerSec: 27472,
    corpusCount: 1890,
    featuresDiscovered: 5120,
    branchCoveragePct: 91.6,
    lineCoveragePct: 89.4,
    edgeCoveragePct: 93.7,
    status: 'PASSED',
    crashCount: 0,
    commitSha: 'f3910ad',
    branch: 'main',
    author: 'mrcoantonioconceicao-ctrl',
    sanitizer: 'UndefinedBehaviorSanitizer (UBSan)',
  },
  {
    id: 'fuzz_run_2026_0831_04',
    target: 'ast_parser',
    targetFile: 'crates/ast/src/parser.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 8).toISOString(),
    durationSeconds: 120,
    totalExecutions: 3710400,
    execSpeedPerSec: 30920,
    corpusCount: 1390,
    featuresDiscovered: 4620,
    branchCoveragePct: 93.8,
    lineCoveragePct: 91.2,
    edgeCoveragePct: 95.4,
    status: 'PASSED',
    crashCount: 0,
    commitSha: 'a10b48c',
    branch: 'main',
    author: 'sec-ci-bot',
    sanitizer: 'AddressSanitizer (ASan)',
  },
  {
    id: 'fuzz_run_2026_0831_05',
    target: 'fuzz_structured_parser',
    targetFile: 'crates/ast/src/structured.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 22).toISOString(),
    durationSeconds: 300,
    totalExecutions: 9840220,
    execSpeedPerSec: 32800,
    corpusCount: 3240,
    featuresDiscovered: 7810,
    branchCoveragePct: 98.1,
    lineCoveragePct: 96.5,
    edgeCoveragePct: 99.0,
    status: 'PASSED',
    crashCount: 0,
    commitSha: '61a8f90',
    branch: 'main',
    author: 'mrcoantonioconceicao-ctrl',
    sanitizer: 'AddressSanitizer (ASan)',
  },
  {
    id: 'fuzz_run_2026_0828_06',
    target: 'ast_parser',
    targetFile: 'crates/ast/src/parser.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 4).toISOString(),
    durationSeconds: 240,
    totalExecutions: 7600000,
    execSpeedPerSec: 31666,
    corpusCount: 2900,
    featuresDiscovered: 6100,
    branchCoveragePct: 92.4,
    lineCoveragePct: 89.8,
    edgeCoveragePct: 94.1,
    status: 'CRASH_DETECTED',
    crashCount: 1,
    severity: 'HIGH',
    commitSha: '4b22777',
    branch: 'feat/lifetime-syntax',
    author: 'dev-contributor',
    sanitizer: 'AddressSanitizer (ASan)',
  },
  {
    id: 'fuzz_run_2026_0824_07',
    target: 'refactor_engine',
    targetFile: 'crates/engine/src/refactor.rs',
    timestamp: new Date(Date.now() - 1000 * 60 * 60 * 24 * 8).toISOString(),
    durationSeconds: 180,
    totalExecutions: 5200000,
    execSpeedPerSec: 28888,
    corpusCount: 2010,
    featuresDiscovered: 5300,
    branchCoveragePct: 90.2,
    lineCoveragePct: 88.0,
    edgeCoveragePct: 92.5,
    status: 'PASSED',
    crashCount: 0,
    commitSha: '8c991e2',
    branch: 'main',
    author: 'sec-ci-automation',
    sanitizer: 'UndefinedBehaviorSanitizer (UBSan)',
  },
];

// Realistic corpus items (seeds & crash payloads)
const INITIAL_CORPORA: FuzzCorpusItem[] = [
  {
    id: 'corp_crash_01',
    target: 'ast_parser',
    targetFile: 'crates/ast/src/parser.rs',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    sizeBytes: 128,
    mutationType: 'Byte Flip & Slice Truncation',
    hexPreview: '5c 78 30 30 72 75 73 74 5f 74 61 72 67 65 74 21 28 5b 75 6e 73 61 66 65 20 7b 20 2a 28 30 78 64 65 61 64 62 65 65 66 20 61 73 20 2a 6d 75 74 20 75 38 29 20 3d 20 34 32 3b 20 7d 5d 29',
    asciiPreview: '\\x00rust_target!([unsafe { *(0xdeadbeef as *mut u8) = 42; }])',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 18).toISOString(),
    triggeredCrash: true,
    severity: 'CRITICAL',
    crashIssueType: 'MEMORY_CORRUPTION (Heap-Buffer-Overflow)',
    coverageImpact: '+18 novas bordas de fluxo em unsafe blocks',
  },
  {
    id: 'corp_seed_02',
    target: 'fuzz_structured_parser',
    targetFile: 'crates/ast/src/structured.rs',
    sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
    sizeBytes: 256,
    mutationType: 'Arbitrary Recursive Type Derivation',
    hexPreview: '66 6e 20 76 65 72 69 66 79 5f 70 71 63 3c 54 3a 20 4b 79 62 65 72 4b 65 6d 3e 28 6b 65 79 3a 20 54 29 20 2d 3e 20 52 65 73 75 6c 74 3c 28 29 2c 20 53 65 63 45 72 72 6f 72 3e 20 7b',
    asciiPreview: 'fn verify_pqc<T: KyberKem>(key: T) -> Result<(), SecError> { ... }',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 55).toISOString(),
    triggeredCrash: false,
    coverageImpact: '+42 novos nós genéricos e traits PQC mapeados',
  },
  {
    id: 'corp_seed_03',
    target: 'refactor_engine',
    targetFile: 'crates/engine/src/refactor.rs',
    sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
    sizeBytes: 512,
    mutationType: 'Crossover AST Tree Splice',
    hexPreview: '75 73 65 20 72 75 73 74 73 68 69 65 6c 64 5f 63 6f 72 65 3a 3a 6d 61 63 72 6f 73 3b 20 23 5b 64 65 72 69 76 65 28 53 65 63 75 72 65 43 6c 6f 6e 65 29 5d 20 73 74 72 75 63 74',
    asciiPreview: 'use rustshield_core::macros; #[derive(SecureClone)] struct Token { ... }',
    discoveredAt: new Date(Date.now() - 1000 * 60 * 140).toISOString(),
    triggeredCrash: false,
    coverageImpact: '+29 derivações de macros expandidas',
  },
  {
    id: 'corp_crash_04',
    target: 'ast_parser',
    targetFile: 'crates/ast/src/parser.rs',
    sha256: '4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a',
    sizeBytes: 94,
    mutationType: 'Dictionary Token Insertion (Malformed Lifetime)',
    hexPreview: '27 61 3a 20 27 73 74 61 74 69 63 20 2b 20 27 75 6e 62 6f 75 6e 64 65 64 20 26 26 20 2a 63 6f 6e 73 74 20 63 5f 63 68 61 72 20 3d 20 4e 55 4c 4c',
    asciiPreview: "'a: 'static + 'unbounded && *const c_char = NULL",
    discoveredAt: new Date(Date.now() - 1000 * 60 * 60 * 24 * 4).toISOString(),
    triggeredCrash: true,
    severity: 'HIGH',
    crashIssueType: 'PANIC_OUT_OF_BOUNDS (Malformed Lifetime Tokenizer)',
    coverageImpact: '+35 ramos de desvio no lexer de lifetimes',
  },
];

export const FuzzingDashboard: React.FC<FuzzingDashboardProps> = ({
  fuzzAlerts = [],
  onTriggerSimulateFuzz,
  onNavigateToTests,
  onNavigateToRefactor,
  onResolveAlert,
  showNotification,
}) => {
  const [runs, setRuns] = useState<FuzzingRunRecord[]>(INITIAL_FUZZ_RUNS);
  const [corpora, setCorpora] = useState<FuzzCorpusItem[]>(INITIAL_CORPORA);

  // Filter & Search states
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedTargetFilter, setSelectedTargetFilter] = useState<string>('ALL');
  const [selectedSeverityFilter, setSelectedSeverityFilter] = useState<string>('ALL');
  const [selectedDateRange, setSelectedDateRange] = useState<'ALL' | '24H' | '7D' | '30D' | 'CUSTOM'>('ALL');
  const [customStartDate, setCustomStartDate] = useState<string>('');
  const [customEndDate, setCustomEndDate] = useState<string>('');
  const [selectedCorpusFilter, setSelectedCorpusFilter] = useState<'ALL' | 'CRASH_ONLY' | 'BENCHMARK_ONLY'>('ALL');

  const [isExecutingFuzz, setIsExecutingFuzz] = useState<boolean>(false);
  const [activeTabSubView, setActiveTabSubView] = useState<'overview' | 'runs' | 'corpora' | 'alerts'>('overview');

  // Modal inspection states
  const [selectedAlertForModal, setSelectedAlertForModal] = useState<FuzzCrashAlert | null>(null);
  const [isAlertModalOpen, setIsAlertModalOpen] = useState<boolean>(false);
  const [copiedHexId, setCopiedHexId] = useState<string | null>(null);

  // Sync with global fuzzAlerts to dynamically augment the crash corpus and run records
  const dynamicRuns = useMemo(() => {
    const alertRunRecords: FuzzingRunRecord[] = fuzzAlerts.map((alt) => ({
      id: `run_live_${alt.id}`,
      target: alt.target,
      targetFile: PARSER_TARGET_FILE_MAP[alt.target]?.file || `crates/ast/src/${alt.target}.rs`,
      timestamp: alt.timestamp,
      durationSeconds: 120,
      totalExecutions: 4200000,
      execSpeedPerSec: 35000,
      corpusCount: 1650,
      featuresDiscovered: 5400,
      branchCoveragePct: 95.8,
      lineCoveragePct: 94.2,
      edgeCoveragePct: 97.5,
      status: alt.status === 'ACTIVE_UNRESOLVED' ? 'CRASH_DETECTED' : 'PASSED',
      crashCount: alt.status === 'ACTIVE_UNRESOLVED' ? 1 : 0,
      severity: (alt.severity as any) || 'CRITICAL',
      commitSha: alt.commitSha || 'live-head',
      branch: alt.branch,
      author: alt.author || 'ci-fuzzer',
      sanitizer: 'AddressSanitizer (ASan)',
    }));

    const existingIds = new Set(alertRunRecords.map((r) => r.id));
    return [...alertRunRecords, ...runs.filter((r) => !existingIds.has(r.id))];
  }, [fuzzAlerts, runs]);

  // Combined corpora list including dynamic payload from fuzzAlerts
  const dynamicCorpora = useMemo(() => {
    const alertCorpora: FuzzCorpusItem[] = fuzzAlerts
      .filter((alt) => alt.crashInputPreview)
      .map((alt) => ({
        id: `corp_alert_${alt.id}`,
        target: alt.target,
        targetFile: PARSER_TARGET_FILE_MAP[alt.target]?.file || `crates/ast/src/${alt.target}.rs`,
        sha256: alt.commitSha ? `sha256_${alt.commitSha}` : 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b',
        sizeBytes: 128,
        mutationType: 'Dynamic LibFuzzer Mutator (Crash Reproduction)',
        hexPreview: alt.crashInputPreview || '',
        asciiPreview: alt.rawErrorLog.slice(0, 75).replace(/[\n\r]/g, ' '),
        discoveredAt: alt.timestamp,
        triggeredCrash: alt.status === 'ACTIVE_UNRESOLVED',
        severity: (alt.severity as any) || 'CRITICAL',
        crashIssueType: `${alt.issueType} (${alt.severity})`,
        coverageImpact: 'Gatilho de falha crítica de integridade de memória',
      }));

    const existingIds = new Set(alertCorpora.map((c) => c.id));
    return [...alertCorpora, ...corpora.filter((c) => !existingIds.has(c.id))];
  }, [fuzzAlerts, corpora]);

  // Helper date checker
  const isDateWithinFilter = (isoDateStr: string) => {
    if (selectedDateRange === 'ALL') return true;
    const itemDate = new Date(isoDateStr).getTime();
    const now = Date.now();

    if (selectedDateRange === '24H') {
      return now - itemDate <= 24 * 60 * 60 * 1000;
    }
    if (selectedDateRange === '7D') {
      return now - itemDate <= 7 * 24 * 60 * 60 * 1000;
    }
    if (selectedDateRange === '30D') {
      return now - itemDate <= 30 * 24 * 60 * 60 * 1000;
    }
    if (selectedDateRange === 'CUSTOM') {
      if (customStartDate && itemDate < new Date(customStartDate).getTime()) {
        return false;
      }
      if (customEndDate) {
        const endDay = new Date(customEndDate).getTime() + 24 * 60 * 60 * 1000;
        if (itemDate > endDay) return false;
      }
      return true;
    }
    return true;
  };

  // Filtered runs with Date, Target (Parser File), and Severity
  const filteredRuns = useMemo(() => {
    return dynamicRuns.filter((r) => {
      // Date filter
      if (!isDateWithinFilter(r.timestamp)) return false;

      // Target / Parser file filter
      if (selectedTargetFilter !== 'ALL' && r.target !== selectedTargetFilter && !r.targetFile.includes(selectedTargetFilter)) {
        return false;
      }

      // Severity filter
      if (selectedSeverityFilter !== 'ALL') {
        if (selectedSeverityFilter === 'NON_CRASH') {
          if (r.status !== 'PASSED' || r.crashCount > 0) return false;
        } else {
          if (r.status !== 'CRASH_DETECTED' || r.severity !== selectedSeverityFilter) return false;
        }
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          r.target.toLowerCase().includes(q) ||
          r.targetFile.toLowerCase().includes(q) ||
          r.commitSha.toLowerCase().includes(q) ||
          r.branch.toLowerCase().includes(q) ||
          r.sanitizer.toLowerCase().includes(q) ||
          (r.severity && r.severity.toLowerCase().includes(q)) ||
          r.author.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [dynamicRuns, selectedTargetFilter, selectedSeverityFilter, selectedDateRange, customStartDate, customEndDate, searchQuery]);

  // Filtered corpora with Date, Target (Parser File), and Severity
  const filteredCorpora = useMemo(() => {
    return dynamicCorpora.filter((c) => {
      // Date filter
      if (!isDateWithinFilter(c.discoveredAt)) return false;

      // Target filter
      if (selectedTargetFilter !== 'ALL' && c.target !== selectedTargetFilter && !c.targetFile.includes(selectedTargetFilter)) {
        return false;
      }

      // Corpus Type filter
      if (selectedCorpusFilter === 'CRASH_ONLY' && !c.triggeredCrash) return false;
      if (selectedCorpusFilter === 'BENCHMARK_ONLY' && c.triggeredCrash) return false;

      // Severity filter
      if (selectedSeverityFilter !== 'ALL') {
        if (selectedSeverityFilter === 'NON_CRASH') {
          if (c.triggeredCrash) return false;
        } else {
          if (!c.triggeredCrash || c.severity !== selectedSeverityFilter) return false;
        }
      }

      // Search query filter
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          c.target.toLowerCase().includes(q) ||
          c.targetFile.toLowerCase().includes(q) ||
          c.mutationType.toLowerCase().includes(q) ||
          c.hexPreview.toLowerCase().includes(q) ||
          c.asciiPreview.toLowerCase().includes(q) ||
          (c.crashIssueType && c.crashIssueType.toLowerCase().includes(q)) ||
          (c.severity && c.severity.toLowerCase().includes(q)) ||
          c.coverageImpact.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [dynamicCorpora, selectedTargetFilter, selectedSeverityFilter, selectedCorpusFilter, selectedDateRange, customStartDate, customEndDate, searchQuery]);

  // Filtered Webhook Alerts
  const filteredAlerts = useMemo(() => {
    return fuzzAlerts.filter((alt) => {
      // Date filter
      if (!isDateWithinFilter(alt.timestamp)) return false;

      // Target filter
      if (selectedTargetFilter !== 'ALL' && alt.target !== selectedTargetFilter) return false;

      // Severity filter
      if (selectedSeverityFilter !== 'ALL') {
        if (selectedSeverityFilter === 'NON_CRASH') return false;
        if (alt.severity !== selectedSeverityFilter) return false;
      }

      // Search Query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return (
          alt.target.toLowerCase().includes(q) ||
          alt.issueType.toLowerCase().includes(q) ||
          alt.severity.toLowerCase().includes(q) ||
          alt.branch.toLowerCase().includes(q) ||
          (alt.commitSha && alt.commitSha.toLowerCase().includes(q)) ||
          alt.rawErrorLog.toLowerCase().includes(q) ||
          (alt.remediationAdvice && alt.remediationAdvice.toLowerCase().includes(q))
        );
      }
      return true;
    });
  }, [fuzzAlerts, selectedTargetFilter, selectedSeverityFilter, selectedDateRange, customStartDate, customEndDate, searchQuery]);

  // Check active filters count
  const activeFiltersCount = useMemo(() => {
    let count = 0;
    if (selectedTargetFilter !== 'ALL') count++;
    if (selectedSeverityFilter !== 'ALL') count++;
    if (selectedDateRange !== 'ALL') count++;
    if (selectedCorpusFilter !== 'ALL') count++;
    if (searchQuery.trim()) count++;
    return count;
  }, [selectedTargetFilter, selectedSeverityFilter, selectedDateRange, selectedCorpusFilter, searchQuery]);

  const handleClearAllFilters = () => {
    setSelectedTargetFilter('ALL');
    setSelectedSeverityFilter('ALL');
    setSelectedDateRange('ALL');
    setCustomStartDate('');
    setCustomEndDate('');
    setSelectedCorpusFilter('ALL');
    setSearchQuery('');
    showNotification('Todos os filtros foram redefinidos.');
  };

  // High-level aggregate metrics
  const aggregateMetrics = useMemo(() => {
    const totalRuns = dynamicRuns.length;
    const totalExecs = dynamicRuns.reduce((acc, r) => acc + r.totalExecutions, 0);
    const avgBranchCoverage = (
      dynamicRuns.reduce((acc, r) => acc + r.branchCoveragePct, 0) / (totalRuns || 1)
    ).toFixed(1);
    const avgLineCoverage = (
      dynamicRuns.reduce((acc, r) => acc + r.lineCoveragePct, 0) / (totalRuns || 1)
    ).toFixed(1);
    const totalCrashesDetected = dynamicRuns.reduce((acc, r) => acc + r.crashCount, 0);
    const activeUnresolvedAlerts = fuzzAlerts.filter((a) => a.status === 'ACTIVE_UNRESOLVED').length;
    const totalCorpusSeeds = dynamicCorpora.length;

    return {
      totalRuns,
      totalExecs,
      avgBranchCoverage: Number(avgBranchCoverage),
      avgLineCoverage: Number(avgLineCoverage),
      totalCrashesDetected,
      activeUnresolvedAlerts,
      totalCorpusSeeds,
    };
  }, [dynamicRuns, dynamicCorpora, fuzzAlerts]);

  const handleCopyHex = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHexId(id);
    showNotification('Payload hexadecimal copiado para a área de transferência.');
    setTimeout(() => setCopiedHexId(null), 2500);
  };

  const handleTriggerFuzzExecution = (target: string) => {
    setIsExecutingFuzz(true);
    showNotification(`⚡ Iniciando sessão de teste de estresse contínuo no target '${target}'...`);

    setTimeout(() => {
      setIsExecutingFuzz(false);
      if (onTriggerSimulateFuzz) {
        onTriggerSimulateFuzz(target);
      } else {
        const newRun: FuzzingRunRecord = {
          id: `fuzz_run_interactive_${Date.now()}`,
          target,
          targetFile: PARSER_TARGET_FILE_MAP[target]?.file || `crates/ast/src/${target}.rs`,
          timestamp: new Date().toISOString(),
          durationSeconds: 120,
          totalExecutions: 4500000,
          execSpeedPerSec: 37500,
          corpusCount: 1980,
          featuresDiscovered: 5800,
          branchCoveragePct: 96.5,
          lineCoveragePct: 94.8,
          edgeCoveragePct: 97.9,
          status: 'PASSED',
          crashCount: 0,
          commitSha: 'int-sess',
          branch: 'interactive-fuzz',
          author: 'dev-operator',
          sanitizer: 'AddressSanitizer (ASan)',
        };
        setRuns((prev) => [newRun, ...prev]);
        showNotification(`✅ Sessão concluída! 4.5M iterações executadas com 96.5% de cobertura de branches.`);
      }
    }, 1800);
  };

  return (
    <div className="space-y-6 animate-fadeIn pb-12">
      {/* Top Header & Overview Bar */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-5">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 shadow-sm">
              <Flame className="h-5 w-5" />
            </div>
            <div>
              <h1 className="text-xl font-mono font-bold text-white tracking-tight flex items-center gap-2">
                <span>Cargo-Fuzz & Memory Safety Cockpit</span>
                <span className="rounded bg-red-500/20 px-2 py-0.5 text-[10px] font-mono font-semibold uppercase text-red-300 border border-red-500/30">
                  LibFuzzer + ASan
                </span>
              </h1>
              <p className="text-xs text-zinc-400 font-sans">
                Monitoramento contínuo de testes de estresse mutacionais, cobertura de código AST e análise pericial de corpora de crash.
              </p>
            </div>
          </div>
        </div>

        {/* Global Action Buttons */}
        <div className="flex items-center gap-2.5 shrink-0 flex-wrap">
          <button
            onClick={() => handleTriggerFuzzExecution(selectedTargetFilter !== 'ALL' ? selectedTargetFilter : 'ast_parser')}
            disabled={isExecutingFuzz}
            className="flex items-center gap-2 rounded-lg bg-red-600 px-3.5 py-2 text-xs font-mono font-bold text-white hover:bg-red-500 transition-all shadow-md shadow-red-950 disabled:opacity-50"
          >
            {isExecutingFuzz ? (
              <>
                <RotateCw className="h-3.5 w-3.5 animate-spin" />
                <span>Executando Fuzzing...</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Disparar Fuzzing ({selectedTargetFilter !== 'ALL' ? selectedTargetFilter : 'ast_parser'})</span>
              </>
            )}
          </button>

          {onNavigateToRefactor && (
            <button
              onClick={onNavigateToRefactor}
              className="flex items-center gap-1.5 rounded-lg border border-purple-500/40 bg-purple-950/40 px-3 py-2 text-xs font-mono text-purple-300 hover:bg-purple-900/50 transition-colors"
            >
              <FileCode2 className="h-3.5 w-3.5" />
              <span>Refatoração AST</span>
            </button>
          )}
        </div>
      </div>

      {/* Hero Metric Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Executions */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Iterações Fuzzing</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-white tracking-tight">
            {(aggregateMetrics.totalExecs / 1000000).toFixed(2)}M
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-[11px] text-zinc-400 font-sans">
            <span className="text-emerald-400 font-mono font-bold">~32.5k exec/s</span>
            <span>em multi-thread LLVM</span>
          </div>
          <div className="absolute right-0 bottom-0 h-1 w-full bg-cyan-500/40" />
        </div>

        {/* Branch & Line Coverage */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Cobertura de Código</span>
            <BarChart3 className="h-4 w-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-emerald-300 tracking-tight">
            {aggregateMetrics.avgBranchCoverage}%
          </div>
          <div className="mt-1 flex items-center gap-2 text-[11px] text-zinc-400 font-sans">
            <span>Branch: <b className="text-zinc-200">{aggregateMetrics.avgBranchCoverage}%</b></span>
            <span>•</span>
            <span>Linhas: <b className="text-zinc-200">{aggregateMetrics.avgLineCoverage}%</b></span>
          </div>
          <div className="absolute right-0 bottom-0 h-1 w-full bg-emerald-500/40" />
        </div>

        {/* Crashes & Memory Safety Incidents */}
        <div className={`rounded-xl border p-4 shadow-sm relative overflow-hidden ${
          aggregateMetrics.activeUnresolvedAlerts > 0
            ? 'border-red-500/50 bg-red-950/20'
            : 'border-zinc-800 bg-zinc-900/60'
        }`}>
          <div className="flex items-center justify-between text-zinc-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Falhas / Memory Safety</span>
            <AlertOctagon className={`h-4 w-4 ${aggregateMetrics.activeUnresolvedAlerts > 0 ? 'text-red-400 animate-pulse' : 'text-zinc-400'}`} />
          </div>
          <div className="flex items-baseline gap-2">
            <div className={`text-2xl font-mono font-bold tracking-tight ${
              aggregateMetrics.activeUnresolvedAlerts > 0 ? 'text-red-400' : 'text-zinc-200'
            }`}>
              {aggregateMetrics.totalCrashesDetected}
            </div>
            {aggregateMetrics.activeUnresolvedAlerts > 0 && (
              <span className="text-xs font-mono font-bold text-red-400 bg-red-500/20 border border-red-500/40 px-1.5 py-0.5 rounded animate-pulse">
                {aggregateMetrics.activeUnresolvedAlerts} ATIVO
              </span>
            )}
          </div>
          <div className="mt-1 text-[11px] text-zinc-400 font-sans">
            {aggregateMetrics.activeUnresolvedAlerts > 0
              ? 'AddressSanitizer detectou heap-overflow'
              : 'Nenhum pânico ou leak detectado'}
          </div>
          <div className={`absolute right-0 bottom-0 h-1 w-full ${
            aggregateMetrics.activeUnresolvedAlerts > 0 ? 'bg-red-500' : 'bg-zinc-700'
          }`} />
        </div>

        {/* Corpora Seeds Mapped */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 shadow-sm relative overflow-hidden">
          <div className="flex items-center justify-between text-zinc-400 mb-2">
            <span className="text-xs font-mono font-semibold uppercase tracking-wider">Corpora & Mutações</span>
            <Database className="h-4 w-4 text-purple-400" />
          </div>
          <div className="text-2xl font-mono font-bold text-purple-300 tracking-tight">
            {aggregateMetrics.totalCorpusSeeds}
          </div>
          <div className="mt-1 text-[11px] text-zinc-400 font-sans">
            Sementes de entrada salvas no repositório
          </div>
          <div className="absolute right-0 bottom-0 h-1 w-full bg-purple-500/40" />
        </div>
      </div>

      {/* ADVANCED MULTI-DIMENSIONAL SEARCH & FILTER CONTROL BAR */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-4 space-y-3.5 shadow-md shadow-black/20">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
          {/* Main Search Input */}
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar por target, arquivo do parser, commit SHA, log de erro, payload hex, mutador..."
              className="w-full pl-10 pr-10 py-2 bg-zinc-950 border border-zinc-800 rounded-lg text-xs font-mono text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-red-500/60 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 p-1"
                title="Limpar busca"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            )}
          </div>

          {/* Quick Select Filter Dropdowns */}
          <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
            {/* Target & Parser File Filter */}
            <div className="flex items-center gap-1.5 bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5">
              <FolderTree className="h-3.5 w-3.5 text-zinc-400" />
              <label htmlFor="fuzz-target-select" className="text-[11px] font-mono text-zinc-400">Target:</label>
              <select
                id="fuzz-target-select"
                value={selectedTargetFilter}
                onChange={(e) => setSelectedTargetFilter(e.target.value)}
                className="bg-transparent text-zinc-200 text-xs font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-zinc-900 text-zinc-200">Todos os Targets</option>
                <option value="ast_parser" className="bg-zinc-900 text-zinc-200">
                  ast_parser (crates/ast/src/parser.rs)
                </option>
                <option value="fuzz_structured_parser" className="bg-zinc-900 text-zinc-200">
                  fuzz_structured_parser (crates/ast/src/structured.rs)
                </option>
                <option value="refactor_engine" className="bg-zinc-900 text-zinc-200">
                  refactor_engine (crates/engine/src/refactor.rs)
                </option>
              </select>
            </div>

            {/* Crash Severity Filter */}
            <div className="flex items-center gap-1.5 bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
              <label htmlFor="fuzz-severity-select" className="text-[11px] font-mono text-zinc-400">Severidade:</label>
              <select
                id="fuzz-severity-select"
                value={selectedSeverityFilter}
                onChange={(e) => setSelectedSeverityFilter(e.target.value)}
                className="bg-transparent text-zinc-200 text-xs font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-zinc-900 text-zinc-200">Todas as Severidades</option>
                <option value="CRITICAL" className="bg-zinc-900 text-red-400">🔴 CRITICAL (Memory Corruption / ASan)</option>
                <option value="HIGH" className="bg-zinc-900 text-amber-400">🟠 HIGH (Panic / Out of Bounds)</option>
                <option value="MEDIUM" className="bg-zinc-900 text-yellow-400">🟡 MEDIUM (Recursion / Timeout)</option>
                <option value="NON_CRASH" className="bg-zinc-900 text-emerald-400">🟢 Sem Falhas (PASSED)</option>
              </select>
            </div>

            {/* Date Range Filter */}
            <div className="flex items-center gap-1.5 bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5">
              <Calendar className="h-3.5 w-3.5 text-cyan-400" />
              <label htmlFor="fuzz-date-select" className="text-[11px] font-mono text-zinc-400">Data:</label>
              <select
                id="fuzz-date-select"
                value={selectedDateRange}
                onChange={(e) => setSelectedDateRange(e.target.value as any)}
                className="bg-transparent text-zinc-200 text-xs font-mono focus:outline-none cursor-pointer"
              >
                <option value="ALL" className="bg-zinc-900 text-zinc-200">Todo o Período</option>
                <option value="24H" className="bg-zinc-900 text-zinc-200">Últimas 24 Horas</option>
                <option value="7D" className="bg-zinc-900 text-zinc-200">Últimos 7 Dias</option>
                <option value="30D" className="bg-zinc-900 text-zinc-200">Últimos 30 Dias</option>
                <option value="CUSTOM" className="bg-zinc-900 text-zinc-200">Intervalo Customizado...</option>
              </select>
            </div>
          </div>
        </div>

        {/* Custom Date Pickers Drawer */}
        {selectedDateRange === 'CUSTOM' && (
          <div className="flex items-center gap-3 pt-2 border-t border-zinc-800/80 animate-fadeIn">
            <span className="text-xs font-mono text-zinc-400">De:</span>
            <input
              type="date"
              value={customStartDate}
              onChange={(e) => setCustomStartDate(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-xs font-mono text-zinc-200 focus:outline-none focus:border-red-500/60"
            />
            <span className="text-xs font-mono text-zinc-400">Até:</span>
            <input
              type="date"
              value={customEndDate}
              onChange={(e) => setCustomEndDate(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-xs font-mono text-zinc-200 focus:outline-none focus:border-red-500/60"
            />
          </div>
        )}

        {/* Active Filter Chips & Summary Badge */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-zinc-800/60 text-xs font-mono">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-zinc-500 text-[11px]">Filtros Ativos ({activeFiltersCount}):</span>

            {selectedTargetFilter !== 'ALL' && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 border border-zinc-700 text-[11px]">
                <span>Target: <b>{selectedTargetFilter}</b></span>
                <button onClick={() => setSelectedTargetFilter('ALL')} className="hover:text-red-400">
                  <X className="h-3 w-3" />
                </button>
              </span>
            )}

            {selectedSeverityFilter !== 'ALL' && (
              <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] border ${
                selectedSeverityFilter === 'CRITICAL'
                  ? 'bg-red-950 text-red-300 border-red-500/40'
                  : selectedSeverityFilter === 'HIGH'
                  ? 'bg-amber-950 text-amber-300 border-amber-500/40'
                  : selectedSeverityFilter === 'NON_CRASH'
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-500/40'
                  : 'bg-zinc-800 text-zinc-300 border-zinc-700'
              }`}>
                <span>Severidade: <b>{selectedSeverityFilter}</b></span>
                <button onClick={() => setSelectedSeverityFilter('ALL')} className="hover:text-white">
                  <X className="h-3 w-3" />
                </button>
              </span>
            )}

            {selectedDateRange !== 'ALL' && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/40 text-[11px]">
                <span>Data: <b>{selectedDateRange}</b></span>
                <button onClick={() => setSelectedDateRange('ALL')} className="hover:text-white">
                  <X className="h-3 w-3" />
                </button>
              </span>
            )}

            {searchQuery && (
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-500/40 text-[11px]">
                <span>Busca: <b>"{searchQuery}"</b></span>
                <button onClick={() => setSearchQuery('')} className="hover:text-white">
                  <X className="h-3 w-3" />
                </button>
              </span>
            )}

            {activeFiltersCount > 0 && (
              <button
                onClick={handleClearAllFilters}
                className="text-[11px] text-red-400 hover:text-red-300 underline font-mono ml-1"
              >
                Limpar Todos
              </button>
            )}
          </div>

          <div className="text-[11px] text-zinc-400 font-mono">
            Mostrando <b className="text-zinc-200">{filteredRuns.length}</b> execuções e <b className="text-zinc-200">{filteredCorpora.length}</b> sementes
          </div>
        </div>
      </div>

      {/* Target Navigation & View Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-zinc-800 pb-3">
        {/* Sub-view switcher */}
        <div className="flex items-center gap-1.5 p-1 bg-zinc-900 border border-zinc-800 rounded-lg">
          <button
            onClick={() => setActiveTabSubView('overview')}
            className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all ${
              activeTabSubView === 'overview'
                ? 'bg-zinc-800 text-white font-bold shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            📊 Visão Geral & Cobertura
          </button>

          <button
            onClick={() => setActiveTabSubView('runs')}
            className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all ${
              activeTabSubView === 'runs'
                ? 'bg-zinc-800 text-white font-bold shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            ⏱️ Histórico de Execuções ({filteredRuns.length})
          </button>

          <button
            onClick={() => setActiveTabSubView('corpora')}
            className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all ${
              activeTabSubView === 'corpora'
                ? 'bg-zinc-800 text-white font-bold shadow-xs'
                : 'text-zinc-400 hover:text-zinc-200'
            }`}
          >
            🧬 Corpora & Entradas ({filteredCorpora.length})
          </button>

          {fuzzAlerts.length > 0 && (
            <button
              onClick={() => setActiveTabSubView('alerts')}
              className={`px-3 py-1.5 text-xs font-mono rounded-md transition-all flex items-center gap-1.5 ${
                activeTabSubView === 'alerts'
                  ? 'bg-red-950/80 border border-red-500/40 text-red-300 font-bold shadow-xs'
                  : 'text-red-400/80 hover:text-red-300'
              }`}
            >
              <AlertOctagon className="h-3.5 w-3.5" />
              <span>Incidentes Webhook ({filteredAlerts.length})</span>
            </button>
          )}
        </div>
      </div>

      {/* VIEW 1: OVERVIEW & COVERAGE BREAKDOWN */}
      {activeTabSubView === 'overview' && (
        <div className="space-y-6">
          {/* Target Breakdown Grid with linked Parser Source Files */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Target 1: ast_parser */}
            <div className={`rounded-xl border p-4 space-y-3 transition-all ${
              selectedTargetFilter === 'ast_parser'
                ? 'border-red-500/60 bg-red-950/20'
                : 'border-zinc-800 bg-zinc-900/50'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-red-400 animate-pulse" />
                  <span className="font-mono font-bold text-sm text-zinc-200">ast_parser</span>
                </div>
                <span className="text-[10px] font-mono text-zinc-400 bg-zinc-800 px-2 py-0.5 rounded">
                  Raw Bytes
                </span>
              </div>

              <div className="rounded bg-black/60 border border-zinc-800/80 p-2 font-mono text-[10px] text-zinc-400 space-y-1">
                <div className="text-zinc-300 flex items-center gap-1">
                  <FileCode2 className="h-3 w-3 text-red-400" />
                  <code>crates/ast/src/parser.rs</code>
                </div>
                <div className="text-zinc-500">
                  Target: <code>fuzz/fuzz_targets/ast_parser.rs</code>
                </div>
              </div>

              <p className="text-xs text-zinc-400 font-sans">
                Parser principal de código AST Rust/TypeScript. Valida resiliência contra malformed AST, tokens truncados e injeções de memória.
              </p>

              {/* Progress Bar: Branch Coverage */}
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between text-[11px] text-zinc-400">
                  <span>Branch Coverage</span>
                  <span className="text-emerald-400 font-bold">94.2%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full" style={{ width: '94.2%' }} />
                </div>
              </div>

              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-xs font-mono">
                <button
                  onClick={() => setSelectedTargetFilter('ast_parser')}
                  className="text-zinc-400 hover:text-zinc-200 text-[11px] underline"
                >
                  Filtrar Este Target
                </button>
                <button
                  onClick={() => handleTriggerFuzzExecution('ast_parser')}
                  disabled={isExecutingFuzz}
                  className="text-red-400 hover:text-red-300 text-[11px] flex items-center gap-1 font-bold"
                >
                  <Play className="h-3 w-3 fill-current" />
                  <span>Fuzz Target</span>
                </button>
              </div>
            </div>

            {/* Target 2: fuzz_structured_parser */}
            <div className={`rounded-xl border p-4 space-y-3 transition-all ${
              selectedTargetFilter === 'fuzz_structured_parser'
                ? 'border-purple-500/60 bg-purple-950/20'
                : 'border-zinc-800 bg-zinc-900/50'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-emerald-400" />
                  <span className="font-mono font-bold text-sm text-zinc-200">fuzz_structured_parser</span>
                </div>
                <span className="text-[10px] font-mono text-purple-300 bg-purple-950/60 border border-purple-500/30 px-2 py-0.5 rounded">
                  Arbitrary AST
                </span>
              </div>

              <div className="rounded bg-black/60 border border-zinc-800/80 p-2 font-mono text-[10px] text-zinc-400 space-y-1">
                <div className="text-zinc-300 flex items-center gap-1">
                  <FileCode2 className="h-3 w-3 text-purple-400" />
                  <code>crates/ast/src/structured.rs</code>
                </div>
                <div className="text-zinc-500">
                  Target: <code>fuzz/fuzz_targets/structured_parser.rs</code>
                </div>
              </div>

              <p className="text-xs text-zinc-400 font-sans">
                Fuzzing guiado por tipos com a crate <code>arbitrary</code>. Gera arquivos de código e estruturas sintáticas sintéticas profundas.
              </p>

              {/* Progress Bar: Branch Coverage */}
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between text-[11px] text-zinc-400">
                  <span>Branch Coverage</span>
                  <span className="text-emerald-400 font-bold">97.4%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full" style={{ width: '97.4%' }} />
                </div>
              </div>

              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-xs font-mono">
                <button
                  onClick={() => setSelectedTargetFilter('fuzz_structured_parser')}
                  className="text-zinc-400 hover:text-zinc-200 text-[11px] underline"
                >
                  Filtrar Este Target
                </button>
                <button
                  onClick={() => handleTriggerFuzzExecution('fuzz_structured_parser')}
                  disabled={isExecutingFuzz}
                  className="text-purple-400 hover:text-purple-300 text-[11px] flex items-center gap-1 font-bold"
                >
                  <Play className="h-3 w-3 fill-current" />
                  <span>Fuzz Target</span>
                </button>
              </div>
            </div>

            {/* Target 3: refactor_engine */}
            <div className={`rounded-xl border p-4 space-y-3 transition-all ${
              selectedTargetFilter === 'refactor_engine'
                ? 'border-blue-500/60 bg-blue-950/20'
                : 'border-zinc-800 bg-zinc-900/50'
            }`}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-blue-400" />
                  <span className="font-mono font-bold text-sm text-zinc-200">refactor_engine</span>
                </div>
                <span className="text-[10px] font-mono text-blue-300 bg-blue-950/60 border border-blue-500/30 px-2 py-0.5 rounded">
                  Patch Generator
                </span>
              </div>

              <div className="rounded bg-black/60 border border-zinc-800/80 p-2 font-mono text-[10px] text-zinc-400 space-y-1">
                <div className="text-zinc-300 flex items-center gap-1">
                  <FileCode2 className="h-3 w-3 text-blue-400" />
                  <code>crates/engine/src/refactor.rs</code>
                </div>
                <div className="text-zinc-500">
                  Target: <code>fuzz/fuzz_targets/refactor_engine.rs</code>
                </div>
              </div>

              <p className="text-xs text-zinc-400 font-sans">
                Motor de refatoração AST e geração automática de correções de segurança em código fonte multi-linguagem.
              </p>

              {/* Progress Bar: Branch Coverage */}
              <div className="space-y-1.5 font-mono text-xs">
                <div className="flex justify-between text-[11px] text-zinc-400">
                  <span>Branch Coverage</span>
                  <span className="text-emerald-400 font-bold">91.6%</span>
                </div>
                <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full" style={{ width: '91.6%' }} />
                </div>
              </div>

              <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-xs font-mono">
                <button
                  onClick={() => setSelectedTargetFilter('refactor_engine')}
                  className="text-zinc-400 hover:text-zinc-200 text-[11px] underline"
                >
                  Filtrar Este Target
                </button>
                <button
                  onClick={() => handleTriggerFuzzExecution('refactor_engine')}
                  disabled={isExecutingFuzz}
                  className="text-blue-400 hover:text-blue-300 text-[11px] flex items-center gap-1 font-bold"
                >
                  <Play className="h-3 w-3 fill-current" />
                  <span>Fuzz Target</span>
                </button>
              </div>
            </div>
          </div>

          {/* Quick Active Alerts Banner if there are any */}
          {fuzzAlerts.filter((a) => a.status === 'ACTIVE_UNRESOLVED').length > 0 && (
            <div className="rounded-xl border border-red-500/50 bg-red-950/30 p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-red-400 font-mono font-bold text-sm">
                  <AlertOctagon className="h-5 w-5 animate-pulse" />
                  <span>Falhas Críticas Detectadas no CI/CD ({fuzzAlerts.filter((a) => a.status === 'ACTIVE_UNRESOLVED').length})</span>
                </div>
                <button
                  onClick={() => setActiveTabSubView('alerts')}
                  className="text-xs font-mono text-red-300 hover:underline flex items-center gap-1"
                >
                  <span>Ver Todos os Detalhes</span>
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </button>
              </div>
              <p className="text-xs text-zinc-300 font-sans">
                O pipeline automatizado do GitHub Actions identificou condições de corrupção de memória durante a execução do fuzzer.
              </p>
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: RUNS HISTORY TABLE */}
      {activeTabSubView === 'runs' && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden shadow-sm">
          <div className="p-4 border-b border-zinc-800 bg-zinc-950/60 flex items-center justify-between">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-zinc-200">
              <Clock className="h-4 w-4 text-zinc-400" />
              <span>Histórico Completo de Execuções (`cargo-fuzz`)</span>
            </div>
            <span className="text-[11px] font-mono text-zinc-400">
              {filteredRuns.length} de {dynamicRuns.length} execuções filtradas
            </span>
          </div>

          {filteredRuns.length === 0 ? (
            <div className="p-8 text-center space-y-2 font-mono text-xs text-zinc-400">
              <p>Nenhuma execução encontrada para os filtros selecionados.</p>
              <button
                onClick={handleClearAllFilters}
                className="text-red-400 hover:underline inline-block"
              >
                Limpar filtros de busca
              </button>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left font-mono text-xs">
                <thead>
                  <tr className="border-b border-zinc-800 text-[10px] uppercase text-zinc-400 bg-zinc-950">
                    <th className="py-3 px-4">Status / Severidade</th>
                    <th className="py-3 px-4">Target / Arquivo Parser</th>
                    <th className="py-3 px-4">Iterações / Duração</th>
                    <th className="py-3 px-4">Velocidade</th>
                    <th className="py-3 px-4">Cobertura (Branch)</th>
                    <th className="py-3 px-4">Corpus</th>
                    <th className="py-3 px-4">Sanitizer</th>
                    <th className="py-3 px-4">Commit / Branch</th>
                    <th className="py-3 px-4">Data / Hora</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800/60">
                  {filteredRuns.map((run) => (
                    <tr key={run.id} className="hover:bg-zinc-800/30 transition-colors">
                      <td className="py-3 px-4">
                        {run.status === 'CRASH_DETECTED' ? (
                          <div className="space-y-0.5">
                            <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-500/40 animate-pulse">
                              <AlertOctagon className="h-3 w-3" />
                              CRASH ({run.crashCount})
                            </span>
                            {run.severity && (
                              <div className="text-[9px] text-red-300 font-bold uppercase">
                                {run.severity}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-500/30">
                            <CheckCircle2 className="h-3 w-3" />
                            PASSED
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-bold text-white">
                          <code>{run.target}</code>
                        </div>
                        <div className="text-[10px] text-zinc-400 font-mono">
                          {run.targetFile}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-zinc-300">
                        <div>{(run.totalExecutions / 1000000).toFixed(2)}M iterações</div>
                        <div className="text-[10px] text-zinc-500">{run.durationSeconds}s runtime</div>
                      </td>
                      <td className="py-3 px-4 text-cyan-300">
                        {run.execSpeedPerSec.toLocaleString()} exec/s
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-emerald-400">{run.branchCoveragePct}%</span>
                          <div className="h-1.5 w-12 rounded-full bg-zinc-800 overflow-hidden">
                            <div
                              className="h-full bg-emerald-500 rounded-full"
                              style={{ width: `${run.branchCoveragePct}%` }}
                            />
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4 text-purple-300 font-bold">
                        {run.corpusCount}
                      </td>
                      <td className="py-3 px-4 text-zinc-400 text-[11px]">
                        {run.sanitizer}
                      </td>
                      <td className="py-3 px-4 text-zinc-400 text-[11px]">
                        <div>{run.branch}</div>
                        <div className="text-zinc-500 font-mono">[{run.commitSha.substring(0, 7)}]</div>
                      </td>
                      <td className="py-3 px-4 text-zinc-400 text-[11px]">
                        {new Date(run.timestamp).toLocaleString('pt-BR')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* VIEW 3: CORPORA & CRASH PAYLOADS */}
      {activeTabSubView === 'corpora' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-zinc-400">Tipo de Entrada:</span>
              <div className="flex items-center gap-1 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
                <button
                  onClick={() => setSelectedCorpusFilter('ALL')}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded ${
                    selectedCorpusFilter === 'ALL' ? 'bg-zinc-800 text-white font-bold' : 'text-zinc-400'
                  }`}
                >
                  Todos ({filteredCorpora.length})
                </button>
                <button
                  onClick={() => setSelectedCorpusFilter('CRASH_ONLY')}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded flex items-center gap-1 ${
                    selectedCorpusFilter === 'CRASH_ONLY'
                      ? 'bg-red-950 text-red-300 font-bold border border-red-500/40'
                      : 'text-red-400/80'
                  }`}
                >
                  <AlertOctagon className="h-3 w-3" />
                  <span>Apenas Crash Inputs ({filteredCorpora.filter((c) => c.triggeredCrash).length})</span>
                </button>
                <button
                  onClick={() => setSelectedCorpusFilter('BENCHMARK_ONLY')}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded ${
                    selectedCorpusFilter === 'BENCHMARK_ONLY' ? 'bg-zinc-800 text-white font-bold' : 'text-zinc-400'
                  }`}
                >
                  Sementes Válidas ({filteredCorpora.filter((c) => !c.triggeredCrash).length})
                </button>
              </div>
            </div>
          </div>

          {filteredCorpora.length === 0 ? (
            <div className="p-8 text-center space-y-2 font-mono text-xs text-zinc-400 rounded-xl border border-zinc-800 bg-zinc-900/40">
              <p>Nenhum corpus ou entrada mutada encontrada para os filtros aplicados.</p>
              <button
                onClick={handleClearAllFilters}
                className="text-red-400 hover:underline inline-block"
              >
                Limpar filtros
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {filteredCorpora.map((corpus) => (
                <div
                  key={corpus.id}
                  className={`rounded-xl border p-4 transition-all ${
                    corpus.triggeredCrash
                      ? 'border-red-900/60 bg-red-950/10 hover:border-red-500/60'
                      : 'border-zinc-800 bg-zinc-900/40 hover:border-zinc-700'
                  }`}
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-zinc-800/80">
                    <div className="flex items-center gap-2.5 flex-wrap">
                      {corpus.triggeredCrash ? (
                        <span className="rounded bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 text-[10px] font-mono font-bold flex items-center gap-1 animate-pulse">
                          <AlertOctagon className="h-3 w-3" />
                          CRASH CORPUS ({corpus.severity || 'CRITICAL'})
                        </span>
                      ) : (
                        <span className="rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-mono font-bold">
                          SEMENTE VÁLIDA
                        </span>
                      )}

                      <span className="font-mono font-bold text-white text-xs">
                        Target: <code>{corpus.target}</code>
                      </span>
                      <span className="text-zinc-400 font-mono text-[11px] hidden sm:inline">
                        • {corpus.targetFile}
                      </span>
                      <span className="text-zinc-500 font-mono text-[11px] hidden sm:inline">
                        • {corpus.sizeBytes} bytes
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-[11px] font-mono text-zinc-400">
                        {new Date(corpus.discoveredAt).toLocaleString('pt-BR')}
                      </span>
                      <button
                        onClick={() => handleCopyHex(corpus.id, corpus.hexPreview)}
                        className="rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 px-2.5 py-1 text-[10px] font-mono flex items-center gap-1 transition-colors"
                        title="Copiar Hexadecimal"
                      >
                        {copiedHexId === corpus.id ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-400" />
                            <span>Copiado!</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" />
                            <span>Copiar Hex</span>
                          </>
                        )}
                      </button>
                    </div>
                  </div>

                  <div className="mt-3 space-y-2">
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-zinc-400">
                      <div>
                        Mutador: <span className="text-zinc-200 font-bold">{corpus.mutationType}</span>
                      </div>
                      {corpus.crashIssueType && (
                        <div className="text-red-400 font-bold">
                          Falha: <span>{corpus.crashIssueType}</span>
                        </div>
                      )}
                      <div className="text-emerald-400">
                        Impacto: <span>{corpus.coverageImpact}</span>
                      </div>
                    </div>

                    {/* Hex & ASCII View Box */}
                    <div className="rounded-lg bg-black/80 p-3 border border-zinc-900 font-mono text-xs space-y-1.5">
                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">
                        Hex Dump Raw Payload:
                      </div>
                      <div className="text-amber-300 break-all select-all text-[11px]">
                        {corpus.hexPreview}
                      </div>

                      <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold pt-1">
                        ASCII Representation:
                      </div>
                      <div className="text-zinc-300 break-all select-all text-[11px] font-mono">
                        {corpus.asciiPreview}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VIEW 4: WEBHOOK CRASH ALERTS */}
      {activeTabSubView === 'alerts' && (
        <div className="space-y-4">
          <div className="rounded-xl border border-red-900/60 bg-red-950/20 p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 font-mono font-bold text-red-300 text-sm">
                <ShieldAlert className="h-5 w-5" />
                <span>Incidentes de Fuzzing Transmitidos via Webhook ({filteredAlerts.length})</span>
              </div>
            </div>
            <p className="text-xs text-zinc-400 mt-1 font-sans">
              Notificações de crash e memory corruption recebidas em tempo real do GitHub Actions.
            </p>
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="p-8 text-center space-y-2 font-mono text-xs text-zinc-400 rounded-xl border border-zinc-800 bg-zinc-900/40">
              <p>Nenhum alerta webhook encontrado para os filtros selecionados.</p>
              <button
                onClick={handleClearAllFilters}
                className="text-red-400 hover:underline inline-block"
              >
                Limpar filtros
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {filteredAlerts.map((alt) => (
                <div
                  key={alt.id}
                  className="rounded-xl border border-red-900/60 bg-zinc-900/80 p-5 space-y-4 shadow-lg shadow-red-950/20"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
                    <div className="flex items-center gap-2.5">
                      <span className="rounded bg-red-500/20 text-red-300 border border-red-500/40 px-2 py-0.5 text-xs font-mono font-bold animate-pulse">
                        {alt.severity} // {alt.issueType}
                      </span>
                      <span className="font-mono text-zinc-200 text-sm font-bold">
                        Target: <code>{alt.target}</code>
                      </span>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono text-zinc-400">
                        {new Date(alt.timestamp).toLocaleString('pt-BR')}
                      </span>
                      <button
                        onClick={() => {
                          setSelectedAlertForModal(alt);
                          setIsAlertModalOpen(true);
                        }}
                        className="rounded bg-red-600 hover:bg-red-500 text-white px-3 py-1.5 text-xs font-mono font-bold flex items-center gap-1.5 transition-colors shadow-xs"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        <span>Inspecionar Crash Log</span>
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                      <span className="text-zinc-500 block text-[10px] uppercase">Branch & PR</span>
                      <span className="text-zinc-200 font-bold">{alt.branch} {alt.prNumber ? `(#${alt.prNumber})` : ''}</span>
                    </div>
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                      <span className="text-zinc-500 block text-[10px] uppercase">Commit SHA</span>
                      <span className="text-zinc-200 font-bold font-mono">{alt.commitSha || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800">
                      <span className="text-zinc-500 block text-[10px] uppercase">Status de Resolução</span>
                      <span className={alt.status === 'ACTIVE_UNRESOLVED' ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>
                        {alt.status}
                      </span>
                    </div>
                  </div>

                  {/* Remediation Summary */}
                  <div className="rounded-lg bg-emerald-950/20 border border-emerald-500/30 p-3 text-xs font-sans text-emerald-200">
                    <b className="font-mono text-emerald-400 uppercase text-[10px] block mb-1">
                      Diretriz Pericial de Correção:
                    </b>
                    {alt.remediationAdvice}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Alert Inspection Modal */}
      <FuzzCrashAlertModal
        isOpen={isAlertModalOpen}
        alert={selectedAlertForModal}
        onClose={() => setIsAlertModalOpen(false)}
        onNavigateToTests={onNavigateToTests}
        onNavigateToRefactor={onNavigateToRefactor}
        onResolveAlert={onResolveAlert}
      />
    </div>
  );
};
