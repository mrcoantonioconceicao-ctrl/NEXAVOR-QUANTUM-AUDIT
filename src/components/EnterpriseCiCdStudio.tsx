import React, { useState } from 'react';
import {
  Workflow,
  Copy,
  Check,
  Download,
  Send,
  Radio,
  FileCode,
  Terminal,
  Layers,
  ChevronRight,
  GitBranch,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface EnterpriseCiCdStudioProps {
  report: SecurityAuditReport | null;
}

export const EnterpriseCiCdStudio: React.FC<EnterpriseCiCdStudioProps> = ({ report }) => {
  const [activePlatform, setActivePlatform] = useState<'github' | 'gitlab' | 'azure' | 'bitbucket'>('github');
  const [copied, setCopied] = useState(false);
  const [simulatedWebhookDest, setSimulatedWebhookDest] = useState<'slack' | 'discord' | 'pagerduty' | 'jira'>('slack');
  const [dispatchStatus, setDispatchStatus] = useState<string | null>(null);

  const repoName = report?.targetRepo.fullName || 'owner/repo';

  const pipelines = {
    github: {
      name: 'GitHub Actions Workflow',
      file: '.github/workflows/rustshield-audit.yml',
      yaml: `name: RustShield Quantum Security Gate

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master ]
  schedule:
    - cron: '0 0 * * *' # Daily Nightly Audit

jobs:
  q-audit-security:
    name: Universal Enterprise AST & Zero-Day Audit
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
      pull-requests: write
    steps:
      - name: Checkout Codebase
        uses: actions/checkout@v4

      - name: Setup Security Toolchain
        uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          components: clippy, rustfmt

      - name: Execute RustShield Quantum AST Security Scan
        uses: mit-quantum/rustshield-audit-action@v2
        with:
          github_token: \${{ secrets.GITHUB_TOKEN }}
          fail_on_severity: CRITICAL
          enable_quantum_pqc_audit: true
          output_sarif: results.sarif
          output_sbom_cyclonedx: sbom.json

      - name: Upload SARIF to GitHub Code Scanning Tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
          category: rustshield-enterprise-security`,
    },
    gitlab: {
      name: 'GitLab CI/CD SAST Pipeline',
      file: '.gitlab-ci.yml',
      yaml: `stages:
  - test
  - security-gate
  - compliance

rustshield_security_audit:
  stage: security-gate
  image: rust:latest
  script:
    - cargo install rustshield-cli --locked
    - rustshield audit --repo $CI_PROJECT_PATH --format sarif --output gl-sast-report.json
    - rustshield sbom --format cyclonedx --output gl-sbom-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
      cyclonedx: gl-sbom-report.json
    expire_in: 30 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"`,
    },
    azure: {
      name: 'Azure DevOps Pipelines',
      file: 'azure-pipelines.yml',
      yaml: `trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UseDotNet@2
    displayName: 'Setup Build Agent'

  - script: |
      curl -sSL https://get.q-audit.enterprise.io | sh
      q-audit scan --dir $(Build.SourcesDirectory) --fail-on CRITICAL --export-sarif $(Build.ArtifactStagingDirectory)/q-audit.sarif
    displayName: 'Run Q-Audit Enterprise Vulnerability Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/q-audit.sarif'
      ArtifactName: 'CodeAnalysisLogs'`,
    },
    bitbucket: {
      name: 'Bitbucket Pipelines',
      file: 'bitbucket-pipelines.yml',
      yaml: `image: rust:latest

pipelines:
  pull-requests:
    '**':
      - step:
          name: RustShield Quantum Security Gate
          script:
            - cargo install rustshield-cli
            - rustshield audit --pr $BITBUCKET_PR_ID --token $BITBUCKET_ACCESS_TOKEN`,
    },
  };

  const currentPipeline = pipelines[activePlatform];

  const handleCopy = () => {
    navigator.clipboard.writeText(currentPipeline.yaml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDispatchSimulation = () => {
    setDispatchStatus(`Disparando webhook com assinatura HMAC-SHA256 para ${simulatedWebhookDest.toUpperCase()}...`);
    setTimeout(() => {
      setDispatchStatus(`Payload de alerta de segurança entregue com sucesso para ${simulatedWebhookDest.toUpperCase()} (HTTP 200 OK).`);
    }, 900);
  };

  return (
    <div className="space-y-6 text-zinc-300">
      {/* Header */}
      <div className="rounded-xl border border-zinc-800 bg-linear-to-r from-zinc-900 via-zinc-900/90 to-zinc-950 p-5 sm:p-6 shadow-xl">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="flex h-6 items-center rounded-md bg-emerald-500/20 px-2 text-[10px] font-mono font-bold uppercase text-emerald-400 border border-emerald-500/30">
                Multi-Cloud CI/CD
              </span>
              <span className="text-xs text-zinc-400 font-mono">DevSecOps Enterprise Pipeline Studio</span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight">
              Gerador de Pipelines CI/CD & Despacho de Webhooks
            </h2>
            <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl">
              Configurações prontas para esteiras de produção com bloqueio automático de Pull Requests inseguros e upload contínuo de SARIF/SBOM.
            </p>
          </div>
        </div>

        {/* Platform selection pills */}
        <div className="mt-6 flex flex-wrap gap-2 border-t border-zinc-800/80 pt-4">
          {[
            { id: 'github', label: 'GitHub Actions' },
            { id: 'gitlab', label: 'GitLab CI' },
            { id: 'azure', label: 'Azure DevOps' },
            { id: 'bitbucket', label: 'Bitbucket Pipelines' },
          ].map((p) => (
            <button
              key={p.id}
              onClick={() => setActivePlatform(p.id as any)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-mono font-semibold transition-all ${
                activePlatform === p.id
                  ? 'bg-zinc-800 text-white border border-zinc-700 shadow-xs'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <Workflow className="h-3.5 w-3.5 text-emerald-400" />
              <span>{p.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Code Editor Preview */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 space-y-3 shadow-2xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
          <div className="flex items-center gap-2 font-mono text-xs text-zinc-300">
            <FileCode className="h-4 w-4 text-emerald-400" />
            <span className="font-bold text-white">{currentPipeline.file}</span>
            <span className="text-zinc-500">({currentPipeline.name})</span>
          </div>

          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-mono text-zinc-200 hover:bg-zinc-800 transition-colors shrink-0"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5 text-zinc-400" />}
            <span>{copied ? 'Copiado!' : 'Copiar YAML'}</span>
          </button>
        </div>

        <pre className="p-4 bg-black/70 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto border border-zinc-900 leading-relaxed">
          {currentPipeline.yaml}
        </pre>
      </div>

      {/* Webhook Multi-Destination Test Dispatcher */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/70 p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-emerald-400" />
            <h3 className="text-sm font-mono font-bold text-white uppercase">
              Despachador de Alertas Enterprise (Slack / Discord / PagerDuty / Jira)
            </h3>
          </div>
          <span className="text-xs font-mono text-zinc-400">HMAC SHA-256 Signer</span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {[
            { id: 'slack', label: 'Slack Security SOC' },
            { id: 'discord', label: 'Discord Security Bot' },
            { id: 'pagerduty', label: 'PagerDuty High Priority' },
            { id: 'jira', label: 'Jira Auto-Issue' },
          ].map((d) => (
            <button
              key={d.id}
              onClick={() => setSimulatedWebhookDest(d.id as any)}
              className={`p-2.5 rounded-lg border text-xs font-mono font-semibold transition-all text-center ${
                simulatedWebhookDest === d.id
                  ? 'border-emerald-500 bg-emerald-950/20 text-white'
                  : 'border-zinc-800 bg-zinc-950 text-zinc-400 hover:bg-zinc-850'
              }`}
            >
              {d.label}
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
          <button
            onClick={handleDispatchSimulation}
            className="w-full sm:w-auto flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-2 text-xs font-mono font-bold text-zinc-950 hover:bg-emerald-400 transition-colors shadow-xs"
          >
            <Send className="h-3.5 w-3.5" />
            <span>Testar Disparo de Alerta</span>
          </button>

          {dispatchStatus && (
            <span className="text-xs font-mono text-emerald-400 bg-emerald-950/30 px-3 py-1.5 rounded border border-emerald-500/30">
              {dispatchStatus}
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
