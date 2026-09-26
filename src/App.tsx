import React, { useState, useEffect } from 'react';
import { Sidebar, TabType } from './components/Sidebar.tsx';
import { TopBar } from './components/TopBar.tsx';
import { AuditInputHero } from './components/AuditInputHero.tsx';
import { AuditDashboard } from './components/AuditDashboard.tsx';
import { WaveTheoryVisualizer } from './components/WaveTheoryVisualizer.tsx';
import { BpmnWorkflowView } from './components/BpmnWorkflowView.tsx';
import { CodeReviewWorkbench } from './components/CodeReviewWorkbench.tsx';
import { SecurityTestSuite } from './components/SecurityTestSuite.tsx';
import { ArchitectureDocsModal } from './components/ArchitectureDocsModal.tsx';
import { ScaleClusterDashboard } from './components/ScaleClusterDashboard.tsx';
import { AuditDiffComparator } from './components/AuditDiffComparator.tsx';
import { WebhookConfigView } from './components/WebhookConfigView.tsx';
import { AstRefactorStudio } from './components/AstRefactorStudio.tsx';
import { GitHubTokenModal } from './components/GitHubTokenModal.tsx';
import { ComplianceGovernanceHub } from './components/ComplianceGovernanceHub.tsx';
import { QuantumPqcHub } from './components/QuantumPqcHub.tsx';
import { GraphRagVisualizer } from './components/GraphRagVisualizer.tsx';
import { EnterpriseCiCdStudio } from './components/EnterpriseCiCdStudio.tsx';
import { EnterpriseAuditTrail } from './components/EnterpriseAuditTrail.tsx';
import { FuzzCrashBanner } from './components/FuzzCrashBanner.tsx';
import { FuzzCrashAlertModal } from './components/FuzzCrashAlertModal.tsx';
import { FuzzingDashboard } from './components/FuzzingDashboard.tsx';
import { getStoredGitHubToken } from './services/tokenStorage.ts';
import { SecurityAuditReport, BpmnStep, FuzzCrashAlert } from './domain/types.ts';

import { INITIAL_BPMN_STEPS, advanceBpmnStep } from './domain/bpmnWorkflow.ts';
import { fetchGitHubRepository } from './services/githubService.ts';
import { runFullSecurityAudit } from './services/auditService.ts';
import { exportExecutivePdf } from './services/pdfExporter.ts';
import { downloadSarifFile } from './services/sarifExporter.ts';
import { saveAuditSession, getAuditHistory, syncHistoryFromFirebase } from './services/auditHistoryService.ts';

const DEFAULT_SANDBOX_REPORT: SecurityAuditReport = {
  id: 'solana_sandbox_counter_initial',
  timestamp: new Date().toISOString(),
  targetRepo: {
    owner: 'solana-labs',
    name: 'solana_sandbox_counter',
    fullName: 'solana-labs/solana_sandbox_counter',
    description: 'Solana Anchor Smart Contract Sandbox Workspace',
    stars: 142,
    forks: 38,
    openIssues: 0,
    defaultBranch: 'main',
    language: 'Rust',
    url: 'https://github.com/solana-labs/solana_sandbox_counter',
    fileCount: 1,
    totalTreeFiles: 1,
  },
  filesAudited: [
    {
      path: 'programs/solana_sandbox_counter/src/lib.rs',
      size: 920,
      content: `use anchor_lang::prelude::*;\n\ndeclare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");\n\n#[program]\npub mod solana_sandbox_counter {\n    use super::*;\n    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {\n        let counter = &mut ctx.accounts.counter;\n        counter.authority = ctx.accounts.authority.key();\n        counter.count = 0;\n        Ok(())\n    }\n}`,
    },
  ],
  overallSecurityScore: 92,
  editionDetected: '2021',
  detectedLanguages: ['Rust'],
  primaryLanguage: 'Rust',
  totalUnsafeBlocks: 0,
  totalLinesAudited: 45,
  vulnerabilities: [
    {
      id: 'VULN-SOL-001',
      title: 'Controle de Acesso em Instruções Anchor',
      severity: 'MEDIUM',
      category: 'BROKEN_ACCESS_AUTH',
      cwe: 'CWE-285',
      cvssScore: 5.3,
      file: 'programs/solana_sandbox_counter/src/lib.rs',
      line: 12,
      description: 'Autoridade atribuída sem restrição explícita has_one na conta do programa.',
      unsafeRiskDetail: 'Mutações de autoridade sem assinatura verificada.',
      waveShockwaveRadius: 'CRATE_BOUNDARY',
      originalSnippet: 'counter.authority = ctx.accounts.authority.key();',
      remediatedSnippet: '#[account(has_one = authority)]\npub counter: Account<\'info, CounterState>,',
      suggestion: 'Adicionar a trava #[account(has_one = authority)] na struct de contexto.',
      miriVerificationStatus: 'COMPLIANT',
    },
  ],
  astMetrics: {
    totalLines: 45,
    codeLines: 35,
    commentLines: 5,
    blankLines: 5,
    cyclomaticComplexity: {
      average: 2.1,
      max: 4,
      highComplexityPoints: 0,
      riskLevel: 'LOW',
      fileBreakdown: [
        {
          file: 'programs/solana_sandbox_counter/src/lib.rs',
          complexity: 2.1,
          functionsCount: 2,
          maxFunctionComplexity: 3,
        },
      ],
    },
    memorySafety: {
      unsafeBlocksCount: 0,
      rawPointerDerefs: 0,
      unboundedSlicingOrAlloc: 0,
      transmuteCount: 0,
      memoryLeakRiskCount: 0,
      memorySafetyIndex: 100,
      memorySafetyPosture: 'OPTIMAL_MEMORY_SAFETY',
    },
  },
  dependencyAnalysis: {
    manifestsScanned: ['Cargo.toml'],
    totalDependenciesCount: 5,
    vulnerableCount: 0,
    rustsecCount: 0,
    outdatedCount: 1,
    vulnerabilities: [],
    outdated: [
      {
        manifestPath: 'Cargo.toml',
        ecosystem: 'Cargo/Rust',
        packageName: 'anchor-lang',
        currentVersion: '0.28.0',
        latestVersion: '0.29.0',
        isMajorBehind: false,
        status: 'OUTDATED',
        remediationCommand: 'cargo update -p anchor-lang',
      },
    ],
  },
  waveHazards: [],
  quantumMetrics: {
    quantumReadinessScore: 95,
    shorAlgorithmVulnerability: 'SAFE',
    groverResistanceBits: 256,
    detectedLegacyPrimitives: [],
    recommendedPqcReplacements: ['ML-KEM-1024', 'Ed25519'],
    constantTimeCompliance: true,
    entropySourceAudit: 'Solana Sysvar Slot Entropy / OS CSPRNG',
  },
  executiveSummary: 'Relatório executivo da auditoria pericial do workspace Solana Anchor.',
  architectureVerdict: {
    dddCompliance: '95% (Bounded Context Isolado)',
    soaResilience: 'Excelente',
    waveTheoryZeroDayPosture: 'Sem Interferência Construtiva Crítica',
    iso27001Status: 'COMPLIANT',
    soc2Status: 'PASS',
    nistSp800Status: 'ALIGNED',
    rustSecAdvisories: 0,
  },
  remediationRoadmap: [
    {
      phase: 'Fase 1: Remediação Urgente',
      priority: 1,
      actions: ['Atualizar restrição #[account(has_one = authority)] no contrato Anchor.'],
      estimatedEffort: '0.5 Horas',
    },
  ],
  securityTests: [],
};

export default function App() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState<boolean>(false);
  const [isMobileSidebarOpen, setIsMobileSidebarOpen] = useState<boolean>(false);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [bpmnSteps, setBpmnSteps] = useState<BpmnStep[]>(INITIAL_BPMN_STEPS);
  const [report, setReport] = useState<SecurityAuditReport | null>(null);
  const [selectedVulnIdForReview, setSelectedVulnIdForReview] = useState<string | null>(null);
  const [notification, setNotification] = useState<string | null>(null);
  const [auditErrorMessage, setAuditErrorMessage] = useState<string | null>(null);
  const [isTokenModalOpen, setIsTokenModalOpen] = useState<boolean>(false);
  const [currentGitHubToken, setCurrentGitHubToken] = useState<string>(() => getStoredGitHubToken());

  // Fuzzing CI/CD Crash Alerts Global State
  const [fuzzAlerts, setFuzzAlerts] = useState<FuzzCrashAlert[]>([]);
  const [activeFuzzAlert, setActiveFuzzAlert] = useState<FuzzCrashAlert | null>(null);
  const [isFuzzModalOpen, setIsFuzzModalOpen] = useState<boolean>(false);
  const [isFuzzBannerDismissed, setIsFuzzBannerDismissed] = useState<boolean>(false);

  // Load existing session history on mount from LocalStorage and sync with Firebase Firestore
  useEffect(() => {
    const history = getAuditHistory();
    if (history.length > 0 && history[0].report) {
      setReport(history[0].report);
      setBpmnSteps((prev) =>
        prev.map((s) => ({ ...s, status: 'COMPLETED', progressPercent: 100 }))
      );
    } else {
      // Auto-run initial audit for embedded Solana Anchor smart contract workspace on first open
      handleStartAuditWithCustomCode(
        'solana_sandbox_counter',
        'programs/solana_sandbox_counter/src/lib.rs',
        `use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod solana_sandbox_counter {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.authority = ctx.accounts.authority.key();
        counter.count = 0;
        counter.bump = ctx.bumps.counter;
        msg!("SolanaSandboxCounter inicializado com sucesso");
        Ok(())
    }

    pub fn increment(ctx: Context<Increment>) -> Result<()> {
        let counter = &mut ctx.accounts.counter;
        counter.count = counter.count.checked_add(1).ok_or(error!(ErrorCode::CounterOverflow))?;
        msg!("Contador incrementado. Novo valor: {}", counter.count);
        Ok(())
    }
}`
      );
    }

    // Background sync with Firestore
    syncHistoryFromFirebase().then((synced) => {
      if (synced && synced.length > 0 && !report) {
        setReport(synced[0].report);
      }
    });

    // Fetch initial Fuzzing Crash alerts
    fetch('/api/webhooks/fuzz-alerts')
      .then((res) => res.json())
      .then((data) => {
        if (data.alerts && Array.isArray(data.alerts)) {
          setFuzzAlerts(data.alerts);
          const firstUnresolved = data.alerts.find((a: FuzzCrashAlert) => a.status === 'ACTIVE_UNRESOLVED');
          if (firstUnresolved) {
            setActiveFuzzAlert(firstUnresolved);
          }
        }
      })
      .catch((err) => console.warn('Could not fetch initial fuzz alerts:', err));

    // Global SSE stream listener for real-time Webhook & Fuzzing Crash notifications
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource('/api/webhooks/stream');

      eventSource.addEventListener('fuzz_crash_alert', (e: any) => {
        try {
          const payload = JSON.parse(e.data);
          if (payload?.alert) {
            setFuzzAlerts((prev) => [payload.alert, ...prev.slice(0, 29)]);
            setActiveFuzzAlert(payload.alert);
            setIsFuzzBannerDismissed(false);
            showNotification(
              `🚨 ALERTA CRÍTICO CI/CD: Cargo-Fuzz detectou Memory Safety Issue no parser (${payload.alert.target})!`
            );
          }
        } catch (err) {
          console.error('Failed to parse SSE fuzz alert:', err);
        }
      });
    } catch (err) {
      console.warn('SSE not supported or connection error:', err);
    }

    return () => {
      if (eventSource) {
        eventSource.close();
      }
    };
  }, []);

  const showNotification = (msg: string) => {
    setNotification(msg);
    setTimeout(() => setNotification(null), 4000);
  };

  const handleStartAuditWithUrl = async (
    url: string,
    token?: string,
    scope: 'FULL_REPO' | 'PULL_REQUEST' = 'FULL_REPO',
    pullNumber?: number
  ) => {
    setIsAuditing(true);
    setAuditErrorMessage(null);
    setBpmnSteps(INITIAL_BPMN_STEPS);
    setActiveTab('bpmn');

    try {
      const scopeLabel = scope === 'PULL_REQUEST' ? 'Pull Request' : 'repositório completo';
      showNotification(`Iniciando ingestão e auditoria de ${scopeLabel}: ${url}...`);
      const { repository, files } = await fetchGitHubRepository({
        url,
        githubToken: token,
        scope,
        pullNumber,
      });

      const auditedReport = await runFullSecurityAudit(
        repository,
        files,
        (stepIndex, progress, msg) => {
          setBpmnSteps((prev) => advanceBpmnStep(prev, stepIndex, progress, msg));
        }
      );

      saveAuditSession(auditedReport);
      setReport(auditedReport);
      setAuditErrorMessage(null);
      showNotification(
        scope === 'PULL_REQUEST'
          ? 'Auditoria de Pull Request concluída com sucesso!'
          : 'Auditoria executiva do repositório concluída!'
      );
      setActiveTab('dashboard');
    } catch (err: any) {
      console.error('Audit failed:', err);
      const errMsg = err?.message || 'Falha ao ler repositório do GitHub.';
      setAuditErrorMessage(errMsg);
      showNotification(`Erro durante auditoria: ${errMsg}`);
      setActiveTab('dashboard');
    } finally {
      setIsAuditing(false);
    }
  };

  const handleStartAuditWithCustomCode = async (
    repoName: string,
    fileName: string,
    code: string
  ) => {
    setIsAuditing(true);
    setAuditErrorMessage(null);
    setBpmnSteps(INITIAL_BPMN_STEPS);
    setActiveTab('bpmn');

    try {
      const repository = {
        owner: 'custom-workspace',
        name: repoName || 'rust-custom-crate',
        fullName: `custom-workspace/${repoName || 'rust-custom-crate'}`,
        description: 'Módulo Rust inserido manualmente para análise pericial',
        stars: 1,
        forks: 0,
        openIssues: 0,
        defaultBranch: 'main',
        language: 'Rust',
        url: 'https://github.com/custom-workspace/rust-custom-crate',
        fileCount: 1,
        totalTreeFiles: 1,
      };

      const files = [{ path: fileName || 'src/lib.rs', size: code.length, content: code }];

      const auditedReport = await runFullSecurityAudit(
        repository,
        files,
        (stepIndex, progress, msg) => {
          setBpmnSteps((prev) => advanceBpmnStep(prev, stepIndex, progress, msg));
        }
      );

      saveAuditSession(auditedReport);
      setReport(auditedReport);
      showNotification('Auditoria de código manual concluída!');
      setActiveTab('dashboard');
    } catch (err: any) {
      console.error('Audit custom code failed:', err);
      showNotification(`Erro: ${err?.message || 'Falha na análise'}`);
    } finally {
      setIsAuditing(false);
    }
  };

  const handleExportPdf = () => {
    if (!report) return;
    try {
      exportExecutivePdf(report);
      showNotification('Relatório Executivo PDF exportado com sucesso!');
    } catch (err: any) {
      console.error('PDF export error:', err);
      showNotification('Erro ao gerar PDF executivo.');
    }
  };

  const handleExportSarif = () => {
    if (!report) return;
    try {
      downloadSarifFile(report);
      showNotification('Arquivo SARIF v2.1.0 (OASIS Standard) baixado com sucesso!');
    } catch (err: any) {
      console.error('SARIF export error:', err);
      showNotification('Erro ao exportar arquivo SARIF.');
    }
  };

  const handleScrollToTopForNewAudit = () => {
    const mainContainer = document.getElementById('main-scroll-container');
    if (mainContainer) {
      mainContainer.scrollTo({ top: 0, behavior: 'smooth' });
    } else {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
    showNotification('Insira ou selecione um repositório para a nova auditoria.');
  };

  return (
    <div className="flex h-screen w-full bg-zinc-950 text-zinc-300 font-sans selection:bg-emerald-500 selection:text-zinc-950 overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar
        activeTab={activeTab}
        onTabChange={(tab) => setActiveTab(tab)}
        isCollapsed={isSidebarCollapsed}
        onToggleCollapse={() => setIsSidebarCollapsed((prev) => !prev)}
        isMobileOpen={isMobileSidebarOpen}
        onCloseMobile={() => setIsMobileSidebarOpen(false)}
        onNewAudit={handleScrollToTopForNewAudit}
        onExportPdf={handleExportPdf}
        onExportSarif={handleExportSarif}
        unresolvedFuzzAlertCount={fuzzAlerts.filter((a) => a.status === 'ACTIVE_UNRESOLVED').length}
        isAuditing={isAuditing}
        report={report}
      />

      {/* Main Content View with Top Header */}
      <div className="flex flex-1 flex-col min-w-0 h-full overflow-hidden">
        {/* Real-time Fuzz Crash Alert Banner */}
        {!isFuzzBannerDismissed && activeFuzzAlert && activeFuzzAlert.status === 'ACTIVE_UNRESOLVED' && (
          <FuzzCrashBanner
            alert={activeFuzzAlert}
            onOpenDetails={() => setIsFuzzModalOpen(true)}
            onDismiss={() => setIsFuzzBannerDismissed(true)}
          />
        )}

        {/* Streamlined Top Header */}
        <TopBar
          activeTab={activeTab}
          onOpenMobileMenu={() => setIsMobileSidebarOpen(true)}
          onNewAudit={handleScrollToTopForNewAudit}
          onExportPdf={handleExportPdf}
          onExportSarif={handleExportSarif}
          onOpenTokenModal={() => setIsTokenModalOpen(true)}
          onOpenFuzzAlertModal={() => setIsFuzzModalOpen(true)}
          unresolvedFuzzAlertCount={fuzzAlerts.filter((a) => a.status === 'ACTIVE_UNRESOLVED').length}
          hasToken={Boolean(currentGitHubToken)}
          isAuditing={isAuditing}
          hasReport={!!report}
        />

        {/* Scrollable Content Area */}
        <main
          id="main-scroll-container"
          className="flex-1 overflow-y-auto overflow-x-hidden min-w-0 pb-12"
        >
          {/* Input Hero at Top */}
          <AuditInputHero
            onStartAuditWithUrl={handleStartAuditWithUrl}
            onStartAuditWithCustomCode={handleStartAuditWithCustomCode}
            isAuditing={isAuditing}
            lastErrorMessage={auditErrorMessage}
            onClearError={() => setAuditErrorMessage(null)}
          />

          {/* Tab Views */}
          {report ? (
            <div className="w-full">
              {activeTab === 'dashboard' && (
                <AuditDashboard
                  report={report}
                  onNavigateToTab={(t) => setActiveTab(t)}
                  onSelectVulnerabilityForReview={(id) => {
                    setSelectedVulnIdForReview(id);
                    setActiveTab('review');
                  }}
                />
              )}

              {activeTab === 'compliance' && (
                <ComplianceGovernanceHub
                  report={report}
                  onOpenVulnReview={(id) => {
                    setSelectedVulnIdForReview(id);
                    setActiveTab('review');
                  }}
                />
              )}

              {activeTab === 'pqc' && (
                <QuantumPqcHub report={report} />
              )}

              {activeTab === 'graphRag' && (
                <GraphRagVisualizer report={report} showNotification={showNotification} />
              )}

              {activeTab === 'cicd' && (
                <EnterpriseCiCdStudio report={report} />
              )}

              {activeTab === 'auditTrail' && (
                <EnterpriseAuditTrail report={report} />
              )}

              {activeTab === 'compare' && (
                <AuditDiffComparator
                  currentReport={report}
                  onNavigateToCodeReview={(vulnId) => {
                    setSelectedVulnIdForReview(vulnId);
                    setActiveTab('review');
                  }}
                  onNavigateToWaves={() => setActiveTab('waves')}
                  onSelectHistoricalReport={(histReport) => {
                    setReport(histReport);
                    showNotification(`Sessão histórica carregada: ${histReport.id}`);
                  }}
                />
              )}

              {activeTab === 'scale10k' && <ScaleClusterDashboard />}

              {activeTab === 'waves' && <WaveTheoryVisualizer report={report} />}

              {activeTab === 'bpmn' && <BpmnWorkflowView steps={bpmnSteps} />}

              {activeTab === 'review' && (
                <CodeReviewWorkbench
                  report={report}
                  selectedVulnId={selectedVulnIdForReview}
                />
              )}

              {activeTab === 'astRefactor' && (
                <AstRefactorStudio
                  report={report}
                  onShowNotification={showNotification}
                />
              )}

              {activeTab === 'tests' && (
                <SecurityTestSuite
                  report={report}
                  onUpdateReport={(updated) => setReport(updated)}
                />
              )}

              {activeTab === 'fuzzing' && (
                <FuzzingDashboard
                  fuzzAlerts={fuzzAlerts}
                  onTriggerSimulateFuzz={(target) => {
                    fetch('/api/webhooks/simulate-fuzz-crash', {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        target,
                        issueType: 'MEMORY_CORRUPTION',
                        repoUrl: report?.targetRepo?.url || 'https://github.com/user/repository',
                      }),
                    })
                      .then((r) => r.json())
                      .then((data) => {
                        if (data.alert) {
                          setFuzzAlerts((prev) => [data.alert, ...prev]);
                          setActiveFuzzAlert(data.alert);
                          setIsFuzzBannerDismissed(false);
                          showNotification(`🚨 Webhook de Crash em '${target}' recebido com sucesso!`);
                        }
                      })
                      .catch((err) => showNotification(`Erro: ${err.message}`));
                  }}
                  onNavigateToTests={() => setActiveTab('tests')}
                  onNavigateToRefactor={() => setActiveTab('astRefactor')}
                  onResolveAlert={(id) => {
                    setFuzzAlerts((prev) =>
                      prev.map((a) => (a.id === id ? { ...a, status: 'RESOLVED' as const } : a))
                    );
                    if (activeFuzzAlert?.id === id) {
                      setActiveFuzzAlert(null);
                    }
                    showNotification('Alerta de crash marcado como resolvido.');
                  }}
                  showNotification={showNotification}
                />
              )}

              {activeTab === 'architecture' && <ArchitectureDocsModal />}

              {activeTab === 'webhooks' && (
                <WebhookConfigView
                  currentRepoUrl={report?.targetRepo?.url}
                  onTriggerAuditFromWebhook={(url) => {
                    handleStartAuditWithUrl(url, undefined, 'FULL_REPO');
                  }}
                  onNavigateToTests={() => setActiveTab('tests')}
                  onNavigateToRefactor={() => setActiveTab('astRefactor')}
                  showNotification={showNotification}
                />
              )}
            </div>

          ) : activeTab === 'compliance' ? (
            <ComplianceGovernanceHub report={null} />
          ) : activeTab === 'pqc' ? (
            <QuantumPqcHub report={null} />
          ) : activeTab === 'graphRag' ? (
            <GraphRagVisualizer report={null} showNotification={showNotification} />
          ) : activeTab === 'fuzzing' ? (
            <FuzzingDashboard
              fuzzAlerts={fuzzAlerts}
              onTriggerSimulateFuzz={(target) => {
                fetch('/api/webhooks/simulate-fuzz-crash', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({
                    target,
                    issueType: 'MEMORY_CORRUPTION',
                    repoUrl: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
                  }),
                })
                  .then((r) => r.json())
                  .then((data) => {
                    if (data.alert) {
                      setFuzzAlerts((prev) => [data.alert, ...prev]);
                      setActiveFuzzAlert(data.alert);
                      setIsFuzzBannerDismissed(false);
                      showNotification(`🚨 Webhook de Crash em '${target}' recebido com sucesso!`);
                    }
                  })
                  .catch((err) => showNotification(`Erro: ${err.message}`));
              }}
              onNavigateToTests={() => setActiveTab('tests')}
              onNavigateToRefactor={() => setActiveTab('astRefactor')}
              onResolveAlert={(id) => {
                setFuzzAlerts((prev) =>
                  prev.map((a) => (a.id === id ? { ...a, status: 'RESOLVED' as const } : a))
                );
                if (activeFuzzAlert?.id === id) {
                  setActiveFuzzAlert(null);
                }
                showNotification('Alerta de crash marcado como resolvido.');
              }}
              showNotification={showNotification}
            />
          ) : activeTab === 'cicd' ? (
            <EnterpriseCiCdStudio report={null} />
          ) : activeTab === 'auditTrail' ? (
            <EnterpriseAuditTrail report={null} />
          ) : activeTab === 'astRefactor' ? (
            <AstRefactorStudio
              report={null}
              onShowNotification={showNotification}
            />
          ) : activeTab === 'webhooks' ? (
            <WebhookConfigView
              currentRepoUrl={undefined}
              onTriggerAuditFromWebhook={(url) => {
                handleStartAuditWithUrl(url, undefined, 'FULL_REPO');
              }}
              onNavigateToTests={() => setActiveTab('tests')}
              onNavigateToRefactor={() => setActiveTab('astRefactor')}
              showNotification={showNotification}
            />
          ) : (
            <AuditDashboard
              report={report || DEFAULT_SANDBOX_REPORT}
              onNavigateToTab={(t) => setActiveTab(t)}
              onSelectVulnerabilityForReview={(id) => {
                setSelectedVulnIdForReview(id);
                setActiveTab('review');
              }}
            />
          )}
        </main>

        {/* Clean Minimalist Footer */}
        <footer className="h-10 shrink-0 bg-zinc-950 border-t border-zinc-900 flex flex-col sm:flex-row items-center justify-between px-4 sm:px-6 text-[9px] uppercase tracking-widest text-zinc-500 font-mono gap-1">
          <span>Confidential // AES-256-GCM Encrypted Output</span>
          <span>RUSTSHIELD SECURE CORE v2.0</span>
          <span className="hidden md:inline">Engine // Native Rust 1.70+</span>
        </footer>
      </div>

      {/* Global Fuzz Crash Memory Safety Alert Modal */}
      <FuzzCrashAlertModal
        isOpen={isFuzzModalOpen}
        alert={activeFuzzAlert}
        onClose={() => setIsFuzzModalOpen(false)}
        onNavigateToTests={() => setActiveTab('tests')}
        onNavigateToRefactor={() => setActiveTab('astRefactor')}
        onResolveAlert={(id) => {
          setFuzzAlerts((prev) =>
            prev.map((a) => (a.id === id ? { ...a, status: 'RESOLVED' as const } : a))
          );
          if (activeFuzzAlert?.id === id) {
            setActiveFuzzAlert(null);
          }
          showNotification('Alerta de crash marcado como resolvido.');
        }}
      />

      {/* GitHub Personal Access Token Modal */}
      <GitHubTokenModal
        isOpen={isTokenModalOpen}
        onClose={() => setIsTokenModalOpen(false)}
        onTokenSaved={(token) => {
          setCurrentGitHubToken(token);
          showNotification(token ? 'Personal Access Token salvo e ativo!' : 'Token removido.');
        }}
      />

      {/* Floating Notification Toast */}
      {notification && (
        <div className="fixed bottom-6 right-6 z-50 rounded border border-zinc-700 bg-zinc-900/95 px-4 py-2.5 text-xs font-mono text-emerald-400 shadow-xl backdrop-blur-md flex items-center gap-2">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
          <span>{notification}</span>
        </div>
      )}
    </div>
  );
}
