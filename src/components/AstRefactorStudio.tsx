import React, { useState, useEffect } from 'react';
import {
  Wand2,
  Cpu,
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  Code2,
  FileCode2,
  Copy,
  Check,
  Sparkles,
  ExternalLink,
  Workflow,
  Layers,
  Box,
  Terminal,
  ShieldCheck,
  Clock,
  Key,
} from 'lucide-react';
import { SecurityAuditReport, SourceFile } from '../domain/types.ts';
import {
  AstRefactorEngine,
  AstAnalysisReport,
  AstViolationNode,
} from '../domain/astRefactorEngine.ts';

interface AstRefactorStudioProps {
  report: SecurityAuditReport | null;
  onShowNotification?: (msg: string) => void;
}

interface GeminiAstRefactorResponse {
  success: boolean;
  source: 'ai-engine' | 'fallback-heuristic-engine';
  refactoredContent: string;
  diffSummary: string;
  astFixesApplied: Array<{
    nodeId: string;
    type: string;
    beforeSnippet: string;
    afterSnippet: string;
    explanation: string;
  }>;
  engineeringHoursSaved: number;
  technicalRationale: string;
  architecturalHighlights: {
    cleanCode: string;
    soaDdd: string;
    bpmnWorkflow: string;
  };
}

const DEFAULT_RUST_LEGACY_CODE = `// ============================================================================
// MODULO RUST LEGADO - VULNERABILIDADES DE MEMORIA & CONCORRENCIA (EXEMPLO)
// ============================================================================

use std::sync::Mutex;

static mut GLOBAL_COUNTERS: Option<Vec<u64>> = None;

pub fn process_legacy_buffer(raw_ptr: *const u8, len: usize) -> Result<u64, String> {
    // 1. AST Violation: Bloco Unsafe sem verificacao de limites
    let value = unsafe {
        let slice = std::slice::from_raw_parts(raw_ptr, len);
        let transmuted: u64 = std::mem::transmute(slice[0]);
        transmuted
    };

    // 2. AST Violation: Invocação de .unwrap() em código principal
    let parsed_number: u64 = "100".parse().unwrap();

    // 3. AST Violation: Modificacao insegura de estado estatico mutavel
    unsafe {
        if GLOBAL_COUNTERS.is_none() {
            GLOBAL_COUNTERS = Some(Vec::new());
        }
        GLOBAL_COUNTERS.as_mut().unwrap().push(value + parsed_number);
    }

    Ok(value + parsed_number)
}
`;

export const AstRefactorStudio: React.FC<AstRefactorStudioProps> = ({
  report,
  onShowNotification,
}) => {
  const [selectedFilePath, setSelectedFilePath] = useState<string>('src/legacy_buffer.rs');
  const [sourceCode, setSourceCode] = useState<string>(DEFAULT_RUST_LEGACY_CODE);
  const [language, setLanguage] = useState<string>('Rust');
  const [astReport, setAstReport] = useState<AstAnalysisReport | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [isRefactoring, setIsRefactoring] = useState<boolean>(false);
  const [refactorResult, setRefactorResult] = useState<GeminiAstRefactorResponse | null>(null);
  const [copiedType, setCopiedType] = useState<string | null>(null);

  // GitHub PR States
  const [githubToken, setGithubToken] = useState<string>('');
  const [isOpeningPr, setIsOpeningPr] = useState<boolean>(false);
  const [prResult, setPrResult] = useState<{
    prUrl: string;
    prNumber: number;
    branch: string;
    isSimulated: boolean;
    message: string;
  } | null>(null);

  // Auto-load first file from audit report if available
  useEffect(() => {
    if (report && report.filesAudited && report.filesAudited.length > 0) {
      const firstFile = report.filesAudited[0];
      setSelectedFilePath(firstFile.path);
      setSourceCode(firstFile.content);
      setLanguage(firstFile.language || 'Rust');
      runAstAnalysis(firstFile.path, firstFile.content, firstFile.language || 'Rust');
    } else {
      runAstAnalysis('src/legacy_buffer.rs', DEFAULT_RUST_LEGACY_CODE, 'Rust');
    }
  }, [report]);

  const runAstAnalysis = (path: string, content: string, lang: string) => {
    setIsAnalyzing(true);
    try {
      const analyzed = AstRefactorEngine.analyzeFile(path, content, lang);
      setAstReport(analyzed);
    } catch (err) {
      console.error('AST Analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSelectAuditedFile = (file: SourceFile) => {
    setSelectedFilePath(file.path);
    setSourceCode(file.content);
    setLanguage(file.language || 'Rust');
    setRefactorResult(null);
    setPrResult(null);
    runAstAnalysis(file.path, file.content, file.language || 'Rust');
  };

  const handleExecuteGeminiRefactor = async () => {
    if (!astReport) return;
    setIsRefactoring(true);
    setPrResult(null);

    try {
      const response = await fetch('/api/audit/ast-refactor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          filePath: astReport.filePath,
          originalContent: astReport.originalContent,
          language: astReport.language,
          astViolations: astReport.violations.map((v) => ({
            nodeId: v.nodeId,
            type: v.type,
            severity: v.severity,
            location: v.location,
            codeSnippet: v.codeSnippet,
            structuralConstraint: v.structuralConstraint,
            recommendation: v.recommendation,
          })),
        }),
      });

      const data = await response.json();
      if (data && data.refactoredContent) {
        setRefactorResult(data);
        if (onShowNotification) {
          onShowNotification('Refatoração guiada por AST + Gemini concluída com sucesso!');
        }
      }
    } catch (err) {
      console.error('Refactor request failed:', err);
      if (onShowNotification) {
        onShowNotification('Erro durante a refatoração por IA.');
      }
    } finally {
      setIsRefactoring(false);
    }
  };

  const handleCreatePullRequest = async () => {
    if (!refactorResult) return;
    setIsOpeningPr(true);

    try {
      const repoUrl = report?.targetRepo?.url || 'https://github.com/custom-workspace/rust-crate';
      const response = await fetch('/api/github/refactor-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl,
          filePath: selectedFilePath,
          refactoredContent: refactorResult.refactoredContent,
          astFixes: refactorResult.astFixesApplied,
          technicalRationale: refactorResult.technicalRationale,
          engineeringHoursSaved: refactorResult.engineeringHoursSaved,
          githubToken,
        }),
      });

      const data = await response.json();
      if (data && data.success) {
        setPrResult({
          prUrl: data.prUrl,
          prNumber: data.prNumber,
          branch: data.branch,
          isSimulated: !!data.isSimulated,
          message: data.message,
        });
        if (onShowNotification) {
          onShowNotification(`Pull Request #${data.prNumber} aberto com sucesso!`);
        }
      }
    } catch (err) {
      console.error('Failed to open PR:', err);
      if (onShowNotification) {
        onShowNotification('Falha ao abrir Pull Request no GitHub.');
      }
    } finally {
      setIsOpeningPr(false);
    }
  };

  const handleCopyCode = (text: string, type: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(type);
    setTimeout(() => setCopiedType(null), 2000);
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300 font-sans">
      {/* Hero Banner */}
      <div className="p-6 rounded-lg bg-gradient-to-r from-purple-950/60 via-zinc-900 to-indigo-950/60 border border-purple-500/30 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/40">
              Bounded Context // AST + IA
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
              Clean Code & SOA
            </span>
          </div>
          <h1 className="text-xl font-bold font-mono text-white flex items-center gap-2">
            <Wand2 className="h-6 w-6 text-purple-400" />
            <span>Refatoração de Código Legado Guiada por AST + Gemini IA</span>
          </h1>
          <p className="text-xs text-zinc-400 max-w-2xl leading-relaxed">
            Validação sintática determinística por Árvore Sintática Abstrata (AST) atuando como restrição inviolável para o raciocínio da IA Generativa (Google Gemini), garantindo compilação estrita e criação automática de Pull Request.
          </p>
        </div>

        {/* Action Trigger */}
        <button
          onClick={handleExecuteGeminiRefactor}
          disabled={isRefactoring || !astReport}
          className="px-5 py-2.5 rounded bg-gradient-to-r from-purple-600 via-indigo-600 to-emerald-600 hover:from-purple-500 hover:to-emerald-500 text-white font-mono text-xs font-bold flex items-center gap-2.5 shadow-lg hover:shadow-purple-500/20 transition-all cursor-pointer disabled:opacity-60 shrink-0"
        >
          {isRefactoring ? (
            <>
              <Cpu className="h-4 w-4 animate-spin text-purple-200" />
              <span>Refatorando AST com Gemini IA...</span>
            </>
          ) : (
            <>
              <Sparkles className="h-4 w-4 text-purple-200" />
              <span>Executar Refatoração AST + Gemini</span>
            </>
          )}
        </button>
      </div>

      {/* File Selector & Controls */}
      <div className="p-4 rounded border border-zinc-800 bg-zinc-950 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <FileCode2 className="h-5 w-5 text-purple-400" />
          <div className="space-y-0.5">
            <label className="text-[10px] font-mono uppercase text-zinc-500 block font-bold">
              Arquivo Alvo para Refatoração
            </label>
            <input
              type="text"
              value={selectedFilePath}
              onChange={(e) => {
                setSelectedFilePath(e.target.value);
                runAstAnalysis(e.target.value, sourceCode, language);
              }}
              className="bg-zinc-900 border border-zinc-800 rounded px-3 py-1.5 text-xs font-mono text-white w-64 focus:border-purple-500 outline-none"
              placeholder="ex: src/legacy_code.rs"
            />
          </div>
        </div>

        {/* Quick Selector if audit report loaded */}
        {report && report.filesAudited && report.filesAudited.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-zinc-500">Do Repositório:</span>
            <div className="flex items-center gap-1.5 overflow-x-auto max-w-md">
              {report.filesAudited.map((file) => (
                <button
                  key={file.path}
                  onClick={() => handleSelectAuditedFile(file)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors cursor-pointer border ${
                    selectedFilePath === file.path
                      ? 'bg-purple-950 text-purple-300 border-purple-500/40 font-bold'
                      : 'bg-zinc-900 text-zinc-400 border-zinc-800 hover:text-zinc-200'
                  }`}
                >
                  {file.path.split('/').pop()}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Main Grid: Source Code + AST Violations */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Col: Source Code Editor / Viewer */}
        <div className="lg:col-span-6 rounded border border-zinc-800 bg-zinc-950 overflow-hidden space-y-0">
          <div className="px-4 py-2.5 bg-zinc-900 border-b border-zinc-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Code2 className="h-4 w-4 text-purple-400" />
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Código Legado ({language})
              </span>
            </div>
            <button
              onClick={() => {
                runAstAnalysis(selectedFilePath, sourceCode, language);
              }}
              className="px-2.5 py-1 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-[10px] font-mono uppercase tracking-wider transition-colors cursor-pointer"
            >
              Reanalisar AST
            </button>
          </div>

          <textarea
            value={sourceCode}
            onChange={(e) => {
              setSourceCode(e.target.value);
              runAstAnalysis(selectedFilePath, e.target.value, language);
            }}
            rows={18}
            className="w-full p-4 bg-zinc-950 font-mono text-xs text-zinc-300 leading-relaxed outline-none border-none resize-none focus:ring-0"
            spellCheck={false}
          />
        </div>

        {/* Right Col: AST Analysis Report & Violations Tree */}
        <div className="lg:col-span-6 rounded border border-zinc-800 bg-zinc-950 p-4 space-y-4">
          <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
            <div className="flex items-center gap-2">
              <Layers className="h-4 w-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                Mapeamento Sintático AST ({astReport?.violations.length || 0} Nós)
              </span>
            </div>
            {astReport && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-500/30">
                Esforço Economizado: ~{astReport.estimatedRefactorHours}h
              </span>
            )}
          </div>

          {/* AST Violations List */}
          <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
            {astReport && astReport.violations.length > 0 ? (
              astReport.violations.map((v) => (
                <div
                  key={v.nodeId}
                  className="p-3.5 rounded bg-zinc-900/60 border border-zinc-800 hover:border-purple-500/30 transition-all space-y-2"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                      <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                      <span>{v.nodeId}</span>
                      <span className="text-zinc-500 text-[10px]">
                        [Linhas {v.location.startLine}-{v.location.endLine}]
                      </span>
                    </span>
                    <span
                      className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded uppercase ${
                        v.severity === 'CRITICAL'
                          ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {v.severity}
                    </span>
                  </div>

                  <p className="text-xs text-zinc-300 font-mono font-semibold">{v.title}</p>

                  <div className="p-2 rounded bg-zinc-950 border border-zinc-800/80">
                    <span className="text-[9px] font-mono uppercase text-zinc-500 block mb-1">
                      Trecho Identificado pela AST:
                    </span>
                    <code className="text-[11px] font-mono text-amber-300 block overflow-x-auto whitespace-pre">
                      {v.codeSnippet}
                    </code>
                  </div>

                  <div className="p-2 rounded bg-purple-950/30 border border-purple-500/20 space-y-1">
                    <span className="text-[9px] font-mono uppercase text-purple-300 font-bold block">
                      Restrição Estrutural Inviolável para IA:
                    </span>
                    <p className="text-[11px] font-mono text-purple-200">
                      {v.structuralConstraint}
                    </p>
                  </div>
                </div>
              ))
            ) : (
              <div className="p-8 text-center space-y-2 border border-dashed border-zinc-800 rounded">
                <CheckCircle2 className="h-8 w-8 text-emerald-400 mx-auto" />
                <p className="text-xs font-mono text-zinc-400">
                  Nenhum nó de violação crítica detectado pela AST no arquivo atual.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Refactor Result View (Side by Side Diff + Architectural Highlights + 1-Click PR) */}
      {refactorResult && (
        <div className="p-6 rounded border border-purple-500/40 bg-zinc-950 space-y-6 shadow-2xl">
          <div className="flex flex-wrap items-center justify-between border-b border-zinc-800 pb-4 gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                  Refatoração AST Aprovada
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  Fonte: {refactorResult.source}
                </span>
              </div>
              <h3 className="text-lg font-bold font-mono text-white flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-400" />
                <span>Resultado da Refatoração Guiada por AST</span>
              </h3>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={() => handleCopyCode(refactorResult.refactoredContent, 'REFACTORED')}
                className="px-3 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
              >
                {copiedType === 'REFACTORED' ? (
                  <>
                    <Check className="h-3.5 w-3.5 text-emerald-400" />
                    <span>Copiado!</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span>Copiar Código Limpo</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Side-by-Side Code Comparison */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Original Code */}
            <div className="rounded border border-red-500/30 bg-zinc-950 overflow-hidden">
              <div className="px-3 py-1.5 bg-red-500/10 border-b border-red-500/20 text-xs font-mono text-red-400 font-bold uppercase">
                Código Legado com Violações AST
              </div>
              <pre className="p-4 text-xs font-mono text-red-200/90 overflow-x-auto bg-zinc-950 leading-relaxed max-h-[360px]">
                {sourceCode}
              </pre>
            </div>

            {/* Refactored Code */}
            <div className="rounded border border-emerald-500/40 bg-zinc-950 overflow-hidden">
              <div className="px-3 py-1.5 bg-emerald-500/10 border-b border-emerald-500/20 text-xs font-mono text-emerald-400 font-bold uppercase flex items-center justify-between">
                <span>Código Refatorado Complacente AST + Clean Code</span>
                <span className="text-[10px] text-emerald-300">Compilável & Idiomático</span>
              </div>
              <pre className="p-4 text-xs font-mono text-emerald-200 overflow-x-auto bg-zinc-950 leading-relaxed max-h-[360px]">
                {refactorResult.refactoredContent}
              </pre>
            </div>
          </div>

          {/* Architectural Breakdown Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded bg-zinc-900/60 border border-emerald-500/30 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400 uppercase">
                <Check className="h-4 w-4" />
                <span>Clean Code em Rust</span>
              </div>
              <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                {refactorResult.architecturalHighlights.cleanCode}
              </p>
            </div>

            <div className="p-4 rounded bg-zinc-900/60 border border-blue-500/30 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-blue-400 uppercase">
                <Box className="h-4 w-4" />
                <span>SOA & Domain-Driven Design</span>
              </div>
              <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                {refactorResult.architecturalHighlights.soaDdd}
              </p>
            </div>

            <div className="p-4 rounded bg-zinc-900/60 border border-amber-500/30 space-y-1.5">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-amber-400 uppercase">
                <Workflow className="h-4 w-4" />
                <span>BPMN 2.0 Orquestração</span>
              </div>
              <p className="text-xs text-zinc-300 font-sans leading-relaxed">
                {refactorResult.architecturalHighlights.bpmnWorkflow}
              </p>
            </div>
          </div>

          {/* Technical Rationale & Saved Hours */}
          <div className="p-4 rounded bg-zinc-900 border border-zinc-800 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-purple-400 uppercase tracking-wider">
                Parecer Técnico do Arquiteto IA
              </span>
              <span className="text-xs font-mono font-bold text-emerald-400 flex items-center gap-1">
                <Clock className="h-3.5 w-3.5" />
                <span>~{refactorResult.engineeringHoursSaved} Horas Economizadas</span>
              </span>
            </div>
            <p className="text-xs text-zinc-300 font-sans leading-relaxed">
              {refactorResult.technicalRationale}
            </p>
          </div>

          {/* 1-Click Pull Request Section */}
          <div className="p-5 rounded-lg bg-gradient-to-r from-zinc-900 via-purple-950/40 to-zinc-900 border border-purple-500/30 space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="space-y-1">
                <h4 className="text-sm font-bold font-mono text-white flex items-center gap-2">
                  <GitPullRequest className="h-4 w-4 text-purple-400" />
                  <span>Abrir Pull Request Oficial no GitHub (1-Click)</span>
                </h4>
                <p className="text-xs text-zinc-400">
                  Gera a branch isolada <code className="text-purple-300">rustshield-legacy-refactor-[timestamp]</code>, realiza o commit do arquivo refatorado e abre o Pull Request com parecer técnico e diff.
                </p>
              </div>

              <button
                onClick={handleCreatePullRequest}
                disabled={isOpeningPr}
                className="px-5 py-2.5 rounded bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-bold flex items-center gap-2 shadow-lg hover:shadow-purple-500/20 transition-all cursor-pointer disabled:opacity-60 shrink-0"
              >
                {isOpeningPr ? (
                  <>
                    <Cpu className="h-4 w-4 animate-spin text-purple-200" />
                    <span>Criando Branch & PR no GitHub...</span>
                  </>
                ) : (
                  <>
                    <GitPullRequest className="h-4 w-4 text-purple-200" />
                    <span>Abrir Pull Request no GitHub</span>
                  </>
                )}
              </button>
            </div>

            {/* Optional Personal Access Token Input */}
            <div className="pt-2 border-t border-zinc-800/80 flex flex-wrap items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2 w-full sm:w-auto">
                <Key className="h-3.5 w-3.5 text-zinc-500" />
                <span className="font-mono text-zinc-400 text-[11px]">GitHub PAT (Opcional):</span>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_xxxxxxxxxxxx"
                  className="bg-zinc-950 border border-zinc-800 rounded px-3 py-1 font-mono text-xs text-white focus:border-purple-500 outline-none w-56"
                />
              </div>

              <span className="text-[10px] font-mono text-zinc-500">
                Alvo: <strong className="text-zinc-300">{report?.targetRepo?.fullName || 'custom-workspace/rust-crate'}</strong>
              </span>
            </div>

            {/* PR Result Banner */}
            {prResult && (
              <div className="p-4 rounded bg-emerald-950/40 border border-emerald-500/40 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-emerald-300 flex items-center gap-2">
                    <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    <span>{prResult.message}</span>
                  </span>
                  <a
                    href={prResult.prUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold flex items-center gap-1.5 transition-colors"
                  >
                    <span>Ver Pull Request</span>
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
                <div className="text-[11px] font-mono text-emerald-200/80 flex items-center gap-4">
                  <span>Branch: <strong>{prResult.branch}</strong></span>
                  <span>PR #{prResult.prNumber}</span>
                  <span>Modo: {prResult.isSimulated ? 'Simulado / Demo' : 'GitHub REST API Direct'}</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
