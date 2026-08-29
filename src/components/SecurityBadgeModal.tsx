import React, { useState } from 'react';
import {
  Shield,
  Copy,
  Check,
  X,
  Code,
  FileText,
  Sparkles,
  ExternalLink,
  Award,
  CheckCircle2,
  Lock,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface SecurityBadgeModalProps {
  report: SecurityAuditReport;
  isOpen: boolean;
  onClose: () => void;
  showNotification?: (msg: string) => void;
}

export type BadgeStyle = 'for-the-badge' | 'flat-square' | 'flat' | 'plastic';

export const SecurityBadgeModal: React.FC<SecurityBadgeModalProps> = ({
  report,
  isOpen,
  onClose,
  showNotification,
}) => {
  const [copiedType, setCopiedType] = useState<string | null>(null);
  const [badgeStyle, setBadgeStyle] = useState<BadgeStyle>('for-the-badge');
  const [includePqcTag, setIncludePqcTag] = useState<boolean>(true);

  if (!isOpen) return null;

  const score = report.securityScore;
  const grade =
    score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 60 ? 'C' : 'F';
  
  const statusText = score >= 80 ? 'PASSED' : score >= 60 ? 'WARNING' : 'FAILED';
  
  const badgeColor =
    score >= 90
      ? '00C853' // bright green
      : score >= 80
      ? '4CAF50' // green
      : score >= 70
      ? 'FFC107' // amber
      : 'F44336'; // red

  const repoFullName = report.targetRepo?.fullName || 'user/repository';
  const targetUrl = report.targetRepo?.url || `https://github.com/${repoFullName}`;

  // Shields.io URL
  const badgeLabel = encodeURIComponent('Q-Audit Security');
  const badgeValue = encodeURIComponent(
    `${score}/100 ${statusText}${includePqcTag ? ' • PQC READY' : ''}`
  );
  
  const shieldsBadgeUrl = `https://img.shields.io/badge/${badgeLabel}-${badgeValue}-${badgeColor}?style=${badgeStyle}&logo=shield&logoColor=white`;

  // Local API SVG endpoint URL (hosted live by applet)
  const origin = typeof window !== 'undefined' ? window.location.origin : 'https://qaudit.ai';
  const localApiSvgUrl = `${origin}/api/badge/svg?repo=${encodeURIComponent(repoFullName)}&score=${score}&grade=${grade}&pqc=${includePqcTag ? '1' : '0'}`;

  // Format templates
  const markdownSnippet = `[![Q-Audit Security Status](${shieldsBadgeUrl})](${targetUrl})`;
  const markdownLocalApiSnippet = `[![Q-Audit Security Status](${localApiSvgUrl})](${targetUrl})`;
  const htmlSnippet = `<a href="${targetUrl}"><img src="${shieldsBadgeUrl}" alt="Q-Audit Security Status: ${score}/100 Grade ${grade}" /></a>`;
  const rstSnippet = `.. image:: ${shieldsBadgeUrl}\n   :target: ${targetUrl}\n   :alt: Q-Audit Security Status`;

  const handleCopy = (text: string, typeKey: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedType(typeKey);
    showNotification?.(`Badge em formato ${label} copiado para a área de transferência!`);
    setTimeout(() => setCopiedType(null), 2500);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-zinc-950/80 backdrop-blur-xs p-4 overflow-y-auto">
      <div className="relative w-full max-w-2xl rounded-xl border border-zinc-800 bg-zinc-900 shadow-2xl overflow-hidden font-sans text-zinc-300">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-zinc-800 bg-zinc-950/60 font-mono">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-emerald-950/60 border border-emerald-500/30 text-emerald-400">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                Gerador de Badge para README.md
              </h3>
              <p className="text-[11px] text-zinc-400 font-sans">
                Selo oficial de auditoria pericial e postura de segurança
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded text-zinc-400 hover:text-white hover:bg-zinc-800 transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* Live Badge Preview Area */}
          <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-5 space-y-4 text-center">
            <div className="text-[10px] uppercase font-mono tracking-widest text-zinc-500">
              Pré-visualização do Selo no GitHub README
            </div>

            <div className="flex flex-col items-center justify-center gap-3 py-3">
              {/* Rendered Badge Image */}
              <a href={targetUrl} target="_blank" rel="noopener noreferrer" className="hover:opacity-90 transition-opacity">
                <img
                  src={shieldsBadgeUrl}
                  alt="Security Audit Status Badge Preview"
                  className="h-7 object-contain drop-shadow-md"
                />
              </a>

              <div className="flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-950/40 border border-emerald-500/30 px-3 py-1 rounded-full">
                <Award className="h-3.5 w-3.5" />
                <span>Score Auditado: <strong>{score}/100 (Nota {grade})</strong></span>
              </div>
            </div>

            {/* Controls: Style & PQC toggle */}
            <div className="pt-3 border-t border-zinc-900 grid grid-cols-1 sm:grid-cols-2 gap-3 text-left">
              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">Estilo do Badge</label>
                <div className="grid grid-cols-2 gap-1.5">
                  {(['for-the-badge', 'flat-square', 'flat', 'plastic'] as BadgeStyle[]).map((s) => (
                    <button
                      key={s}
                      onClick={() => setBadgeStyle(s)}
                      className={`px-2.5 py-1.5 rounded text-[11px] font-mono border transition-all ${
                        badgeStyle === s
                          ? 'bg-emerald-950 border-emerald-500/50 text-emerald-300 font-bold'
                          : 'bg-zinc-900 border-zinc-800 text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-[11px] font-mono text-zinc-400 mb-1">Recursos no Selo</label>
                <button
                  onClick={() => setIncludePqcTag(!includePqcTag)}
                  className={`w-full px-3 py-2 rounded border text-xs font-mono flex items-center justify-between transition-colors ${
                    includePqcTag
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300'
                      : 'bg-zinc-900 border-zinc-800 text-zinc-400'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <Lock className="h-3.5 w-3.5 text-emerald-400" />
                    Tag Criptografia PQC (NIST)
                  </span>
                  <span className="text-[10px] font-bold uppercase">{includePqcTag ? 'SIM' : 'NÃO'}</span>
                </button>
              </div>
            </div>
          </div>

          {/* Snippet Code Blocks */}
          <div className="space-y-4">
            {/* 1. Markdown Snippet (Shields.io) */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <FileText className="h-3.5 w-3.5 text-emerald-400" />
                  Sintaxe Markdown (Recomendado para README.md)
                </span>
                <button
                  onClick={() => handleCopy(markdownSnippet, 'md', 'Markdown')}
                  className="px-2.5 py-1 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-xs font-mono text-emerald-400 flex items-center gap-1.5 transition-colors"
                >
                  {copiedType === 'md' ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span>Copiado!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copiar Markdown</span>
                    </>
                  )}
                </button>
              </div>
              <div className="relative">
                <pre className="p-3 bg-zinc-950 border border-zinc-800 rounded text-xs text-zinc-300 font-mono overflow-x-auto whitespace-pre-wrap break-all select-all">
                  {markdownSnippet}
                </pre>
              </div>
            </div>

            {/* 2. HTML Snippet */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-zinc-300 flex items-center gap-1.5">
                  <Code className="h-3.5 w-3.5 text-blue-400" />
                  Sintaxe HTML Embed
                </span>
                <button
                  onClick={() => handleCopy(htmlSnippet, 'html', 'HTML')}
                  className="px-2.5 py-1 rounded border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-xs font-mono text-zinc-300 flex items-center gap-1.5 transition-colors"
                >
                  {copiedType === 'html' ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span>Copiado!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copiar HTML</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 bg-zinc-950 border border-zinc-800 rounded text-xs text-zinc-400 font-mono overflow-x-auto whitespace-pre-wrap break-all select-all">
                {htmlSnippet}
              </pre>
            </div>

            {/* 3. Direct SVG API Endpoint */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-zinc-300 flex items-center gap-1.5">
                  <Sparkles className="h-3.5 w-3.5 text-amber-400" />
                  URL Direta SVG da API (Hospedada)
                </span>
                <button
                  onClick={() => handleCopy(localApiSvgUrl, 'url', 'URL SVG')}
                  className="px-2.5 py-1 rounded border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-xs font-mono text-zinc-300 flex items-center gap-1.5 transition-colors"
                >
                  {copiedType === 'url' ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-emerald-400" />
                      <span>Copiado!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      <span>Copiar Link SVG</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="p-3 bg-zinc-950 border border-zinc-800 rounded text-xs text-amber-300/90 font-mono overflow-x-auto whitespace-pre-wrap break-all select-all">
                {localApiSvgUrl}
              </pre>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-zinc-800 bg-zinc-950/60 flex items-center justify-between text-xs font-mono text-zinc-500">
          <div className="flex items-center gap-1.5 text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            <span>Compatível com GitHub, GitLab, Bitbucket & Docs</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded bg-zinc-800 hover:bg-zinc-700 text-white transition-colors"
          >
            Fechar
          </button>
        </div>
      </div>
    </div>
  );
};
