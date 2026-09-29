import React, { useState } from 'react';
import {
  Globe,
  Search,
  ExternalLink,
  ShieldAlert,
  Sparkles,
  RefreshCw,
  Copy,
  Check,
  CheckCircle2,
  FileText,
  Radio,
  Cpu,
  Layers,
  Flame,
  ArrowRight,
} from 'lucide-react';
import { searchThreatIntelligence, ThreatIntelSearchResponse } from '../services/threatIntelService.ts';

interface ThreatIntelSearchHubProps {
  initialQuery?: string;
  onShowNotification?: (msg: string) => void;
}

export const ThreatIntelSearchHub: React.FC<ThreatIntelSearchHubProps> = ({
  initialQuery = 'Solana Anchor #[account(has_one)] authority check vulnerability',
  onShowNotification,
}) => {
  const [query, setQuery] = useState(initialQuery);
  const [category, setCategory] = useState<'CVE' | 'ZERO_DAY' | 'SUPPLY_CHAIN' | 'SOLANA_SECURITY' | 'RUST_MEM_SAFETY' | 'PQC_NIST'>('SOLANA_SECURITY');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ThreatIntelSearchResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const presets = [
    { label: 'Solana Anchor has_one Bypass', q: 'Solana Anchor account has_one authority bypass exploit advisory', cat: 'SOLANA_SECURITY' as const },
    { label: 'Rust Tokio Concurrency Races', q: 'Rust tokio sync RwLock memory safety and deadlocks recent advisories', cat: 'RUST_MEM_SAFETY' as const },
    { label: 'NIST ML-KEM PQC Vulnerabilities', q: 'NIST FIPS 203 ML-KEM post-quantum side channel vulnerability advisories', cat: 'PQC_NIST' as const },
    { label: 'Crates.io Supply Chain Advisory', q: 'RustSec supply chain malicious crates typo-squatting advisories', cat: 'SUPPLY_CHAIN' as const },
    { label: 'Anchor PDA Bump Canonicalization', q: 'Solana anchor program derived address bump seed canonicalization vulnerability', cat: 'SOLANA_SECURITY' as const },
    { label: 'Solana Sysvar Slot Entropy Flaw', q: 'Solana on-chain randomness sysvar slot manipulation security audit', cat: 'ZERO_DAY' as const },
  ];

  const handleSearch = async (overrideQ?: string, overrideCat?: typeof category) => {
    const q = (overrideQ !== undefined ? overrideQ : query).trim();
    if (!q) return;

    const cat = overrideCat || category;
    setLoading(true);

    try {
      const data = await searchThreatIntelligence(q, cat);
      setResult(data);
      if (onShowNotification) {
        onShowNotification(`Inteligência recuperada via Google Search Grounding: ${data.sources.length} fontes consultadas.`);
      }
    } catch (e: any) {
      if (onShowNotification) {
        onShowNotification(`Erro ao consultar Google Search Grounding: ${e?.message || 'Falha de rede'}`);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    if (!result) return;
    navigator.clipboard.writeText(result.analysis);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    if (onShowNotification) {
      onShowNotification('Análise copiada para a área de transferência.');
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 sm:p-6">
      {/* Banner de Apresentação do Google Search Data Grounding */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-blue-950/40 via-zinc-900 to-purple-950/30 border border-blue-500/30 p-6 sm:p-8 shadow-2xl">
        <div className="absolute top-0 right-0 p-8 opacity-10 pointer-events-none">
          <Globe className="w-64 h-64 text-blue-400" />
        </div>

        <div className="relative z-10 space-y-4">
          <div className="flex flex-wrap items-center gap-2.5">
            <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/30">
              <Globe className="w-3.5 h-3.5 animate-spin-slow" />
              Google Search Data Grounding
            </span>
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/20">
              <Sparkles className="w-3 h-3 text-purple-400" />
              gemini-3.5-flash
            </span>
            <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <CheckCircle2 className="w-3 h-3" />
              Fontes & Citações Verificadas em Tempo Real
            </span>
          </div>

          <h2 className="text-2xl sm:text-3xl font-bold font-mono text-white tracking-tight">
            Threat Intelligence & CVEs ao Vivo
          </h2>
          <p className="text-zinc-300 text-sm max-w-3xl leading-relaxed">
            Consulte a web aberta em tempo real utilizando o poder do <strong>Google Search Grounding</strong>. Obtenha relatórios técnicos precisos de advisories oficiais do RustSec, vulnerabilidades em smart contracts Anchor/Solana, CVEs emergentes, e atualizações de migração NIST PQC com links diretos para as fontes originais.
          </p>
        </div>
      </div>

      {/* Caixa de Pesquisa Interativa */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 p-5 space-y-4 shadow-lg backdrop-blur-sm">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Digite um CVE, crate, vulnerability em Solana, zero-day ou biblioteca..."
              className="w-full bg-zinc-950 border border-zinc-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus:outline-none focus:border-blue-500 transition-colors font-mono"
            />
          </div>

          <select
            value={category}
            onChange={(e) => setCategory(e.target.value as any)}
            className="bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2.5 text-xs font-mono text-zinc-300 focus:outline-none focus:border-blue-500"
          >
            <option value="SOLANA_SECURITY">Solana / Anchor Security</option>
            <option value="RUST_MEM_SAFETY">Rust Memory Safety & Concurrency</option>
            <option value="CVE">Vulnerabilidade / CVE Geral</option>
            <option value="SUPPLY_CHAIN">Supply Chain & Crates.io</option>
            <option value="PQC_NIST">Pós-Quântica (NIST FIPS 203/204)</option>
            <option value="ZERO_DAY">Exploit / Zero-Day Wave Theory</option>
          </select>

          <button
            onClick={() => handleSearch()}
            disabled={loading || !query.trim()}
            className="inline-flex items-center justify-center gap-2 px-6 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-bold transition-all disabled:opacity-50 disabled:pointer-events-none shadow-lg shadow-blue-600/20"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                Buscando no Google...
              </>
            ) : (
              <>
                <Globe className="w-4 h-4" />
                Buscar com Google Grounding
              </>
            )}
          </button>
        </div>

        {/* Chips de Sugestões / Presets */}
        <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-zinc-800/60">
          <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">Sugestões:</span>
          {presets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => {
                setQuery(p.q);
                setCategory(p.cat);
                handleSearch(p.q, p.cat);
              }}
              className="text-[11px] font-mono px-2.5 py-1 rounded bg-zinc-950 hover:bg-zinc-800 text-zinc-300 hover:text-white border border-zinc-800 hover:border-blue-500/50 transition-colors flex items-center gap-1"
            >
              <span>{p.label}</span>
              <ArrowRight className="w-2.5 h-2.5 opacity-50" />
            </button>
          ))}
        </div>
      </div>

      {/* Resultados Grounded */}
      {result && (
        <div className="space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          {/* Card Principal da Análise */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/90 overflow-hidden shadow-xl">
            {/* Topbar do Resultado */}
            <div className="p-4 sm:p-5 bg-zinc-950/80 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono font-medium ${
                  result.grounded
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                }`}>
                  <Globe className="w-3.5 h-3.5" />
                  {result.grounded ? 'Google Search Data Grounding Ativo' : 'Base Heurística Consolidada'}
                </span>
                <span className="text-xs font-mono text-zinc-400">
                  {new Date(result.timestamp).toLocaleTimeString()}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopy}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-mono transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copiado!' : 'Copiar Análise'}
                </button>
              </div>
            </div>

            {/* Consultas disparadas no Google Search */}
            {result.searchQueries && result.searchQueries.length > 0 && (
              <div className="px-5 py-3 bg-zinc-950/50 border-b border-zinc-800/60 flex flex-wrap items-center gap-2 text-xs font-mono text-zinc-400">
                <span className="text-zinc-500 flex items-center gap-1">
                  <Search className="w-3 h-3" /> Queries Web:
                </span>
                {result.searchQueries.map((sq, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-300">
                    "{sq}"
                  </span>
                ))}
              </div>
            )}

            {/* Corpo do Texto / Análise */}
            <div className="p-6 prose prose-invert max-w-none text-sm text-zinc-200 leading-relaxed font-sans space-y-4">
              <div className="whitespace-pre-wrap font-sans">
                {result.analysis}
              </div>
            </div>

            {/* Seção de Fontes e Citações Verificadas (Grounding Chunks) */}
            {result.sources && result.sources.length > 0 && (
              <div className="p-5 bg-zinc-950/90 border-t border-zinc-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono font-bold text-zinc-300 uppercase tracking-wider flex items-center gap-2">
                    <ExternalLink className="w-3.5 h-3.5 text-blue-400" />
                    Fontes Oficiais & Citações da Web ({result.sources.length})
                  </h4>
                  <span className="text-[11px] font-mono text-zinc-500">
                    Verificado via Google Search Grounding
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {result.sources.map((src, i) => (
                    <a
                      key={i}
                      href={src.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="group flex flex-col justify-between p-3 rounded-lg border border-zinc-800 bg-zinc-900/60 hover:bg-zinc-800/80 hover:border-blue-500/50 transition-all text-xs"
                    >
                      <div className="font-mono text-zinc-200 group-hover:text-blue-400 line-clamp-2 transition-colors font-medium">
                        {src.title || src.url}
                      </div>
                      <div className="mt-2 text-[10px] text-zinc-500 font-mono flex items-center justify-between truncate">
                        <span className="truncate max-w-[200px]">{src.url.replace(/^https?:\/\//, '')}</span>
                        <ExternalLink className="w-3 h-3 text-zinc-500 group-hover:text-blue-400 shrink-0 ml-1" />
                      </div>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
