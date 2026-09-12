import React, { useState, useEffect } from 'react';
import {
  GitPullRequest,
  CheckCircle2,
  AlertTriangle,
  Key,
  ExternalLink,
  ShieldCheck,
  CheckSquare,
  Square,
  Eye,
  EyeOff,
  Cpu,
  FileCode,
  Lock,
  GitBranch,
  Sparkles,
  ChevronRight,
  Info,
} from 'lucide-react';
import { getStoredGitHubToken, setStoredGitHubToken } from '../services/tokenStorage.ts';

export interface GitHubPrAutomationModuleProps {
  filePath: string;
  refactoredContent: string;
  originalContent: string;
  astFixes: Array<{
    nodeId: string;
    type: string;
    beforeSnippet?: string;
    afterSnippet?: string;
    explanation: string;
  }>;
  technicalRationale: string;
  engineeringHoursSaved: number;
  initialRepoUrl?: string;
  onShowNotification?: (msg: string) => void;
}

export const GitHubPrAutomationModule: React.FC<GitHubPrAutomationModuleProps> = ({
  filePath,
  refactoredContent,
  astFixes,
  technicalRationale,
  engineeringHoursSaved,
  initialRepoUrl,
  onShowNotification,
}) => {
  // User Approval State
  const [approveCodeChange, setApproveCodeChange] = useState<boolean>(false);
  const [approveDraftPolicy, setApproveDraftPolicy] = useState<boolean>(false);

  // Configuration State
  const [githubToken, setGithubToken] = useState<string>(() => getStoredGitHubToken());
  const [showToken, setShowToken] = useState<boolean>(false);
  const [targetRepoUrl, setTargetRepoUrl] = useState<string>(
    () => initialRepoUrl || 'https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT'
  );
  const [customPrTitle, setCustomPrTitle] = useState<string>(
    () => `[DRAFT] [RustShield Quantum] Remediação AST: ${filePath.split('/').pop() || filePath}`
  );
  const [customCommitMessage, setCustomCommitMessage] = useState<string>(
    () => `refactor(ast-ai): remediação de segurança em ${filePath} [RustShield Quantum]`
  );
  const [showBodyPreview, setShowBodyPreview] = useState<boolean>(false);

  // PR Execution State
  const [isOpeningPr, setIsOpeningPr] = useState<boolean>(false);
  const [prError, setPrError] = useState<string | null>(null);
  const [executionStep, setExecutionStep] = useState<number>(0);
  const [prResult, setPrResult] = useState<{
    prUrl: string;
    prNumber?: number;
    branch: string;
    filePath: string;
    message: string;
  } | null>(null);

  // Update repo URL if prop changes
  useEffect(() => {
    if (initialRepoUrl) {
      setTargetRepoUrl(initialRepoUrl);
    }
  }, [initialRepoUrl]);

  // Update default PR title when file changes
  useEffect(() => {
    const fileName = filePath.split('/').pop() || filePath;
    setCustomPrTitle(`[DRAFT] [RustShield Quantum] Remediação AST: ${fileName}`);
    setCustomCommitMessage(`refactor(ast-ai): remediação de segurança em ${filePath} [RustShield Quantum]`);
    setPrResult(null);
    setPrError(null);
  }, [filePath]);

  const handleTokenChange = (val: string) => {
    const clean = val.trim();
    setGithubToken(clean);
    setStoredGitHubToken(clean);
  };

  const isApproved = approveCodeChange && approveDraftPolicy;
  const isFormValid = isApproved && Boolean(githubToken.trim()) && Boolean(targetRepoUrl.trim());

  const handleCreatePullRequest = async () => {
    if (!isFormValid) {
      if (!isApproved) {
        setPrError('Por favor, marque as duas caixas de aprovação do usuário para confirmar as correções de segurança.');
      } else if (!githubToken.trim()) {
        setPrError('Insira um GitHub Personal Access Token (PAT) com permissão "repo" para autorizar a operação.');
      } else {
        setPrError('Informe a URL do repositório GitHub de destino.');
      }
      return;
    }

    setIsOpeningPr(true);
    setPrError(null);
    setPrResult(null);
    setExecutionStep(1);

    try {
      // Step 1: Resolvendo Repositório
      setExecutionStep(1);
      await new Promise((r) => setTimeout(r, 400));

      // Step 2: Criando branch isolada
      setExecutionStep(2);

      const response = await fetch('/api/github/refactor-pr', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repoUrl: targetRepoUrl.trim(),
          filePath,
          refactoredContent,
          astFixes,
          technicalRationale,
          engineeringHoursSaved,
          githubToken: githubToken.trim(),
          prTitle: customPrTitle.trim(),
          commitMessage: customCommitMessage.trim(),
        }),
      });

      setExecutionStep(3);
      const data = await response.json().catch(() => null);

      if (response.ok && data && data.success) {
        setExecutionStep(4);
        setPrResult({
          prUrl: data.prUrl,
          prNumber: data.prNumber,
          branch: data.branch,
          filePath: data.filePath || filePath,
          message: data.message || `Pull Request criado com sucesso no GitHub!`,
        });

        if (onShowNotification) {
          onShowNotification(
            data.prNumber
              ? `Pull Request #${data.prNumber} criado com sucesso no GitHub!`
              : `Branch '${data.branch}' criada e enviada para o GitHub!`
          );
        }
      } else {
        const errorMsg =
          data?.error || data?.details || 'Falha ao acionar a API do GitHub para criar o Pull Request.';
        setPrError(errorMsg);
        if (onShowNotification) {
          onShowNotification(`Erro: ${errorMsg}`);
        }
      }
    } catch (err: any) {
      console.error('Erro de conexão ao abrir Pull Request:', err);
      const errorMsg = err?.message || 'Erro de comunicação com o servidor backend.';
      setPrError(errorMsg);
      if (onShowNotification) {
        onShowNotification(`Erro ao criar Pull Request: ${errorMsg}`);
      }
    } finally {
      setIsOpeningPr(false);
    }
  };

  const previewBody = `## 🛡️ [DRAFT] RustShield Quantum v2.5 - AST + IA Security Refactoring

> ⚠️ **POLÍTICA HUMAN-IN-THE-LOOP (DRAFT PR)**
> Aprovado pelo usuário para remediação do arquivo \`${filePath}\`.

### 🎯 Arquivo Remediado:
\`${filePath}\`

### 🔍 Correções Aplicadas (${astFixes.length} Nós AST):
${astFixes.map((f) => `- **${f.nodeId}** (${f.type}): ${f.explanation}`).join('\n')}

### 💡 Parecer Técnico:
${technicalRationale}

### ⏱️ Tempo de Engenharia Economizado: ~${engineeringHoursSaved}h`;

  return (
    <div className="p-6 rounded-lg bg-gradient-to-r from-zinc-950 via-purple-950/30 to-zinc-950 border border-purple-500/40 shadow-2xl space-y-6 text-zinc-300 font-sans">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b border-zinc-800/80 pb-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-purple-500/20 text-purple-300 border border-purple-500/40 flex items-center gap-1">
              <Sparkles className="h-3 w-3 text-purple-300" />
              Módulo de Automação de Pull Request
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1">
              <ShieldCheck className="h-3 w-3 text-emerald-300" />
              Aprovação Human-in-the-Loop
            </span>
          </div>
          <h3 className="text-lg font-bold font-mono text-white flex items-center gap-2">
            <GitPullRequest className="h-5 w-5 text-purple-400" />
            <span>Abertura Automatizada de Pull Request no GitHub</span>
          </h3>
          <p className="text-xs text-zinc-400 max-w-2xl leading-relaxed">
            Após revisar e aprovar as correções sugeridas pela IA, este módulo cria uma branch isolada e submete o Pull Request diretamente ao repositório configurado via API REST do GitHub.
          </p>
        </div>

        <div className="px-3 py-1.5 rounded bg-zinc-900 border border-zinc-800 flex items-center gap-2 shrink-0">
          <FileCode className="h-4 w-4 text-purple-400" />
          <div className="font-mono text-xs">
            <span className="text-zinc-500 block text-[9px] uppercase font-bold">Arquivo Alvo:</span>
            <span className="text-white font-bold">{filePath}</span>
          </div>
        </div>
      </div>

      {/* Step 1: User Approval Gate (Checkboxes) */}
      <div className="p-4 rounded-md bg-zinc-900/90 border border-zinc-800 space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-300 uppercase tracking-wider">
          <Lock className="h-4 w-4 text-purple-400" />
          <span>Passo 1: Aprovação do Usuário (Validação de Segurança)</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {/* Checkbox 1 */}
          <button
            type="button"
            onClick={() => setApproveCodeChange(!approveCodeChange)}
            className={`p-3 rounded border text-left flex items-start gap-3 transition-all cursor-pointer ${
              approveCodeChange
                ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            {approveCodeChange ? (
              <CheckSquare className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <Square className="h-5 w-5 text-zinc-500 shrink-0 mt-0.5" />
            )}
            <div className="space-y-0.5">
              <span className="text-xs font-bold font-mono text-white block">
                Aprovar Código Refatorado & Correções AST
              </span>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Confirmo a análise técnica e aprovo a substituição dos {astFixes.length} nó(s) de código vulnerável em <code className="text-purple-300">{filePath}</code>.
              </p>
            </div>
          </button>

          {/* Checkbox 2 */}
          <button
            type="button"
            onClick={() => setApproveDraftPolicy(!approveDraftPolicy)}
            className={`p-3 rounded border text-left flex items-start gap-3 transition-all cursor-pointer ${
              approveDraftPolicy
                ? 'bg-emerald-950/30 border-emerald-500/50 text-emerald-200'
                : 'bg-zinc-950 border-zinc-800 text-zinc-400 hover:border-zinc-700'
            }`}
          >
            {approveDraftPolicy ? (
              <CheckSquare className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
            ) : (
              <Square className="h-5 w-5 text-zinc-500 shrink-0 mt-0.5" />
            )}
            <div className="space-y-0.5">
              <span className="text-xs font-bold font-mono text-white block">
                Política Human-in-the-Loop (Draft PR)
              </span>
              <p className="text-[11px] text-zinc-400 leading-snug">
                Reconheço que o PR será aberto em modo Draft para revisão do Security Lead antes de eventual fusão no repositório principal.
              </p>
            </div>
          </button>
        </div>
      </div>

      {/* Step 2: Configuration Panel (GitHub Token & Repo) */}
      <div className="p-4 rounded-md bg-zinc-900/90 border border-zinc-800 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-300 uppercase tracking-wider">
            <Key className="h-4 w-4 text-purple-400" />
            <span>Passo 2: Configuração do Repositório & Credenciais GitHub</span>
          </div>

          {githubToken ? (
            <span className="text-[10px] font-mono text-emerald-400 font-bold flex items-center gap-1 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-500/30">
              <CheckCircle2 className="h-3 w-3" /> Token PAT Configurado
            </span>
          ) : (
            <span className="text-[10px] font-mono text-amber-400 font-bold flex items-center gap-1 bg-amber-950/50 px-2 py-0.5 rounded border border-amber-500/30">
              <AlertTriangle className="h-3 w-3" /> Requer Token PAT
            </span>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* PAT Token Input */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-bold block">
              GitHub Personal Access Token (PAT):
            </label>
            <div className="relative">
              <input
                type={showToken ? 'text' : 'password'}
                value={githubToken}
                onChange={(e) => handleTokenChange(e.target.value)}
                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                className="w-full bg-zinc-950 border border-purple-500/40 focus:border-purple-400 rounded px-3 py-2 pr-10 font-mono text-xs text-white outline-none shadow-inner"
              />
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="absolute right-2.5 top-2.5 text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
                title={showToken ? 'Ocultar Token' : 'Exibir Token'}
              >
                {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            <p className="text-[10px] text-zinc-500 font-mono">
              Salvo localmente no seu navegador (`rustshield_github_pat`). Requer escopo <code className="text-purple-300">repo</code>.
            </p>
          </div>

          {/* Target Repo URL Input */}
          <div className="space-y-1.5">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-bold block">
              URL do Repositório GitHub Alvo:
            </label>
            <input
              type="text"
              value={targetRepoUrl}
              onChange={(e) => setTargetRepoUrl(e.target.value)}
              placeholder="https://github.com/usuario/repositorio"
              className="w-full bg-zinc-950 border border-zinc-700 focus:border-purple-400 rounded px-3 py-2 font-mono text-xs text-white outline-none shadow-inner"
            />
            <p className="text-[10px] text-zinc-500 font-mono">
              Suporta repositórios públicos e privados do GitHub.
            </p>
          </div>
        </div>

        {/* PR Custom Title & Commit Message */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-zinc-800">
          <div className="space-y-1">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-bold block">
              Título do Pull Request:
            </label>
            <input
              type="text"
              value={customPrTitle}
              onChange={(e) => setCustomPrTitle(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 focus:border-purple-400 rounded px-3 py-1.5 font-mono text-xs text-white outline-none"
            />
          </div>

          <div className="space-y-1">
            <label className="text-[10px] font-mono uppercase text-zinc-400 font-bold block">
              Mensagem de Commit (Git):
            </label>
            <input
              type="text"
              value={customCommitMessage}
              onChange={(e) => setCustomCommitMessage(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-800 focus:border-purple-400 rounded px-3 py-1.5 font-mono text-xs text-white outline-none"
            />
          </div>
        </div>

        {/* PR Markdown Body Preview Toggle */}
        <div className="pt-2">
          <button
            type="button"
            onClick={() => setShowBodyPreview(!showBodyPreview)}
            className="text-[11px] font-mono text-purple-400 hover:text-purple-300 flex items-center gap-1 cursor-pointer transition-colors"
          >
            <Info className="h-3.5 w-3.5" />
            <span>{showBodyPreview ? 'Ocultar Prévia da Descrição do PR' : 'Exibir Prévia da Descrição do PR (Markdown)'}</span>
          </button>

          {showBodyPreview && (
            <div className="mt-2 p-3 rounded bg-zinc-950 border border-zinc-800 font-mono text-xs text-zinc-300 overflow-x-auto whitespace-pre-wrap leading-relaxed max-h-48">
              {previewBody}
            </div>
          )}
        </div>
      </div>

      {/* Step 3: Execution Trigger & Live Steps Indicator */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-2">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
          <GitBranch className="h-4 w-4 text-purple-400" />
          <span>Branch Gerada:</span>
          <code className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-purple-300 font-bold">
            rustshield-legacy-refactor-[timestamp]
          </code>
        </div>

        <button
          type="button"
          onClick={handleCreatePullRequest}
          disabled={isOpeningPr || !isFormValid}
          className={`px-6 py-3 rounded-md font-mono text-xs font-bold flex items-center gap-2.5 shadow-xl transition-all cursor-pointer shrink-0 ${
            isFormValid
              ? 'bg-gradient-to-r from-purple-600 via-indigo-600 to-emerald-600 hover:from-purple-500 hover:to-emerald-500 text-white shadow-purple-900/30'
              : 'bg-zinc-800 text-zinc-500 border border-zinc-700 cursor-not-allowed opacity-60'
          }`}
        >
          {isOpeningPr ? (
            <>
              <Cpu className="h-4 w-4 animate-spin text-purple-200" />
              <span>Processando Automação no GitHub...</span>
            </>
          ) : (
            <>
              <GitPullRequest className="h-4 w-4 text-purple-200" />
              <span>Aprovar & Abrir Pull Request no GitHub</span>
            </>
          )}
        </button>
      </div>

      {/* Live Execution Progress Bar */}
      {isOpeningPr && (
        <div className="p-4 rounded-md bg-purple-950/30 border border-purple-500/40 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-purple-200">
            <span className="font-bold flex items-center gap-2">
              <Cpu className="h-4 w-4 animate-spin text-purple-400" />
              <span>Executando Orquestração de Pull Request...</span>
            </span>
            <span>Etapa {executionStep} de 4</span>
          </div>

          <div className="grid grid-cols-4 gap-2 text-[10px] font-mono pt-1">
            <div className={`p-1.5 rounded text-center border ${executionStep >= 1 ? 'bg-purple-900/50 border-purple-400 text-purple-200' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
              1. Resolver Repo
            </div>
            <div className={`p-1.5 rounded text-center border ${executionStep >= 2 ? 'bg-purple-900/50 border-purple-400 text-purple-200' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
              2. Criar Branch
            </div>
            <div className={`p-1.5 rounded text-center border ${executionStep >= 3 ? 'bg-purple-900/50 border-purple-400 text-purple-200' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
              3. Commit Atômico
            </div>
            <div className={`p-1.5 rounded text-center border ${executionStep >= 4 ? 'bg-emerald-900/50 border-emerald-400 text-emerald-200 font-bold' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
              4. Abrir PR API
            </div>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {prError && (
        <div className="p-4 rounded-md bg-red-950/60 border border-red-500/60 space-y-1.5">
          <div className="flex items-start gap-2.5 text-xs font-mono font-bold text-red-200">
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-red-200 font-bold">{prError}</p>
              <p className="text-[11px] text-red-300 font-normal leading-relaxed">
                Verifique se o seu GitHub Personal Access Token (PAT) possui permissão <code className="text-white">repo</code> e se o usuário possui permissão de escrita no repositório configurado.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Success Result Card */}
      {prResult && (
        <div className="p-5 rounded-md bg-gradient-to-r from-emerald-950/60 via-zinc-900 to-emerald-950/60 border border-emerald-500/60 shadow-xl space-y-3">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                <span className="text-sm font-bold font-mono text-emerald-300">
                  {prResult.message}
                </span>
              </div>
              <p className="text-xs text-zinc-300 font-mono">
                Arquivo <code className="text-emerald-300 font-bold">{prResult.filePath}</code> remediado e enviado na branch <code className="text-purple-300">{prResult.branch}</code>.
              </p>
            </div>

            <a
              href={prResult.prUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="px-4 py-2 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold flex items-center gap-2 transition-all shadow-lg hover:shadow-emerald-500/20 shrink-0"
            >
              <span>Ver Pull Request no GitHub</span>
              <ExternalLink className="h-4 w-4" />
            </a>
          </div>

          <div className="p-2.5 rounded bg-zinc-950/80 border border-emerald-500/30 flex flex-wrap items-center justify-between gap-4 text-[11px] font-mono text-zinc-300">
            <span>Branch: <strong className="text-purple-300">{prResult.branch}</strong></span>
            {prResult.prNumber && <span>PR Oficial: <strong className="text-emerald-400">#{prResult.prNumber}</strong></span>}
            <span>API: <strong className="text-white">GitHub REST API v3</strong></span>
            <span>Status: <strong className="text-emerald-400">DRAFT (Aguardando Review)</strong></span>
          </div>
        </div>
      )}
    </div>
  );
};
