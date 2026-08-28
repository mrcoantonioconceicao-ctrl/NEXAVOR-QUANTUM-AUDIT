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
import { EnterpriseCiCdStudio } from './components/EnterpriseCiCdStudio.tsx';
import { EnterpriseAuditTrail } from './components/EnterpriseAuditTrail.tsx';
import { getStoredGitHubToken } from './services/tokenStorage.ts';
import { SecurityAuditReport, BpmnStep } from './domain/types.ts';

import { INITIAL_BPMN_STEPS, advanceBpmnStep } from './domain/bpmnWorkflow.ts';
import { BENCHMARK_CASES } from './domain/benchmarks.ts';
import { fetchGitHubRepository } from './services/githubService.ts';
import { runFullSecurityAudit } from './services/auditService.ts';
import { exportExecutivePdf } from './services/pdfExporter.ts';
import { downloadSarifFile } from './services/sarifExporter.ts';
import { saveAuditSession, getAuditHistory, syncHistoryFromFirebase } from './services/auditHistoryService.ts';

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

  // Load existing session history on mount from LocalStorage and sync with Firebase Firestore
  useEffect(() => {
    const history = getAuditHistory();
    if (history.length > 0 && history[0].report) {
      setReport(history[0].report);
      setBpmnSteps((prev) =>
        prev.map((s) => ({ ...s, status: 'COMPLETED', progressPercent: 100 }))
      );
    }

    // Background sync with Firestore
    syncHistoryFromFirebase().then((synced) => {
      if (synced && synced.length > 0 && !report) {
        setReport(synced[0].report);
      }
    });
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
        isAuditing={isAuditing}
        report={report}
      />

      {/* Main Content View with Top Header */}
      <div className="flex flex-1 flex-col min-w-0 h-full overflow-hidden">
        {/* Streamlined Top Header */}
        <TopBar
          activeTab={activeTab}
          onOpenMobileMenu={() => setIsMobileSidebarOpen(true)}
          onNewAudit={handleScrollToTopForNewAudit}
          onExportPdf={handleExportPdf}
          onExportSarif={handleExportSarif}
          onOpenTokenModal={() => setIsTokenModalOpen(true)}
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

              {activeTab === 'architecture' && <ArchitectureDocsModal />}

              {activeTab === 'webhooks' && (
                <WebhookConfigView
                  currentRepoUrl={report?.targetRepo?.url}
                  onTriggerAuditFromWebhook={(url) => {
                    handleStartAuditWithUrl(url, undefined, 'FULL_REPO');
                  }}
                  showNotification={showNotification}
                />
              )}
            </div>

          ) : activeTab === 'compliance' ? (
            <ComplianceGovernanceHub report={null} />
          ) : activeTab === 'pqc' ? (
            <QuantumPqcHub report={null} />
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
              showNotification={showNotification}
            />
          ) : (
            <div className="max-w-4xl mx-auto p-12 text-center space-y-4">
              <div className="inline-flex p-3 rounded-full bg-zinc-900 border border-zinc-800 text-emerald-400">
                <span className="h-4 w-4 rounded-full bg-emerald-500 animate-pulse" />
              </div>
              <h3 className="text-lg font-mono font-bold text-white uppercase tracking-wider">
                Pronto para Auditoria Pericial Real
              </h3>
              <p className="text-xs text-zinc-400 font-sans max-w-lg mx-auto leading-relaxed">
                Insira a URL de um repositório do GitHub (público ou privado) ou cole o código fonte no Editor Manual acima para iniciar a varredura pericial ao vivo via inteligência artificial (Gemini API).
              </p>
            </div>
          )}
        </main>

        {/* Clean Minimalist Footer */}
        <footer className="h-10 shrink-0 bg-zinc-950 border-t border-zinc-900 flex flex-col sm:flex-row items-center justify-between px-4 sm:px-6 text-[9px] uppercase tracking-widest text-zinc-500 font-mono gap-1">
          <span>Confidential // AES-GCM Encrypted Output</span>
          <span>MIT QUANTUM LABS</span>
          <span className="hidden md:inline">Engine // Rust-Hardened</span>
        </footer>
      </div>

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
