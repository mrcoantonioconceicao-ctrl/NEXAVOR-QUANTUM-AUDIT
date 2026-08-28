import React, { useState, useEffect } from 'react';
import { Key, Lock, CheckCircle2, AlertCircle, ExternalLink, Trash2, Eye, EyeOff } from 'lucide-react';
import { getStoredGitHubToken, setStoredGitHubToken } from '../services/tokenStorage.ts';

interface GitHubTokenModalProps {
  isOpen: boolean;
  onClose: () => void;
  onTokenSaved?: (token: string) => void;
}

export const GitHubTokenModal: React.FC<GitHubTokenModalProps> = ({
  isOpen,
  onClose,
  onTokenSaved,
}) => {
  const [tokenInput, setTokenInput] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [testStatus, setTestStatus] = useState<{ loading: boolean; message: string | null; isError: boolean }>({
    loading: false,
    message: null,
    isError: false,
  });

  useEffect(() => {
    if (isOpen) {
      setTokenInput(getStoredGitHubToken());
      setSavedSuccess(false);
      setTestStatus({ loading: false, message: null, isError: false });
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = () => {
    const clean = tokenInput.trim();
    setStoredGitHubToken(clean);
    setSavedSuccess(true);
    onTokenSaved?.(clean);
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 1200);
  };

  const handleClear = () => {
    setTokenInput('');
    setStoredGitHubToken('');
    setSavedSuccess(false);
    onTokenSaved?.('');
    setTestStatus({ loading: false, message: 'Token removido com sucesso.', isError: false });
  };

  const handleTestToken = async () => {
    const clean = tokenInput.trim();
    if (!clean) {
      setTestStatus({ loading: false, message: 'Insira um token para testar.', isError: true });
      return;
    }

    setTestStatus({ loading: true, message: 'Validando token na API do GitHub...', isError: false });
    try {
      const authHeader = clean.startsWith('Bearer ') || clean.startsWith('token ') ? clean : `token ${clean}`;
      const res = await fetch('https://api.github.com/user', {
        headers: {
          Authorization: authHeader,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'RustShield-Quantum-Audit-Bot/2.5',
        },
      });

      if (res.ok) {
        const user = await res.json();
        setTestStatus({
          loading: false,
          message: `Token Autêntico! Autenticado como @${user.login} (${user.name || 'GitHub User'})`,
          isError: false,
        });
      } else {
        const err = await res.json().catch(() => ({}));
        setTestStatus({
          loading: false,
          message: `Falha na validação (HTTP ${res.status}): ${err.message || 'Token inválido ou sem permissão.'}`,
          isError: true,
        });
      }
    } catch (e: any) {
      setTestStatus({
        loading: false,
        message: `Erro ao conectar com GitHub: ${e?.message || 'Erro de rede.'}`,
        isError: true,
      });
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-xs p-4">
      <div className="w-full max-w-xl rounded-xl border border-zinc-800 bg-zinc-900 p-6 space-y-5 shadow-2xl font-mono text-xs">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
              <Key className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                GitHub Personal Access Token (PAT)
              </h3>
              <p className="text-[11px] text-zinc-400 font-sans">
                Liberar criação de Pull Requests e acesso a repositórios privados
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-zinc-500 hover:text-white text-lg font-bold px-2 py-1 rounded hover:bg-zinc-800"
          >
            ✕
          </button>
        </div>

        {/* Content & Instruction */}
        <div className="space-y-3 font-sans text-xs text-zinc-300">
          <p className="leading-relaxed">
            Para que o RustShield abra <strong>Pull Requests automáticos</strong> no seu repositório GitHub (refatorações de código, correções AST e remediação de dependências), cole abaixo o seu Personal Access Token.
          </p>

          <div className="p-3 rounded bg-zinc-950 border border-zinc-800 space-y-2 font-mono text-[11px]">
            <div className="flex items-center justify-between text-zinc-400 font-bold uppercase">
              <span>Instrução de Permissões no GitHub:</span>
              <a
                href="https://github.com/settings/tokens/new?scopes=repo&description=RustShield+Quantum+Token"
                target="_blank"
                rel="noopener noreferrer"
                className="text-emerald-400 hover:underline flex items-center gap-1 font-normal text-[10px]"
              >
                <span>Criar Token no GitHub</span>
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
            <p className="text-zinc-400 text-[11px] leading-snug font-sans">
              No GitHub, vá em <strong>Settings &gt; Developer Settings &gt; Personal access tokens (classic)</strong> e marque a caixa de seleção <code className="text-emerald-400 bg-zinc-900 px-1 py-0.5 rounded">repo</code> (Full control of private repositories).
            </p>
          </div>
        </div>

        {/* Token Input Box */}
        <div className="space-y-2 font-mono">
          <label className="text-[10px] text-emerald-400 uppercase font-bold flex items-center justify-between">
            <span>Cole seu Token (ghp_... ou github_pat_...):</span>
            {getStoredGitHubToken() && (
              <span className="text-emerald-400 flex items-center gap-1 text-[10px]">
                <CheckCircle2 className="h-3 w-3" /> Token Salvo no Navegador
              </span>
            )}
          </label>
          <div className="relative">
            <input
              type={showToken ? 'text' : 'password'}
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
              className="w-full pl-3 pr-20 py-2.5 rounded bg-zinc-950 border border-emerald-500/50 text-white font-mono text-xs focus:outline-none focus:border-emerald-400 shadow-inner"
            />
            <div className="absolute right-2 top-2 flex items-center gap-1">
              <button
                type="button"
                onClick={() => setShowToken(!showToken)}
                className="p-1 rounded text-zinc-400 hover:text-white hover:bg-zinc-800"
                title={showToken ? 'Ocultar Token' : 'Mostrar Token'}
              >
                {showToken ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
              {tokenInput && (
                <button
                  type="button"
                  onClick={handleClear}
                  className="p-1 rounded text-rose-400 hover:text-rose-300 hover:bg-rose-950/50"
                  title="Remover Token"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Test Status Feedback */}
        {testStatus.message && (
          <div
            className={`p-3 rounded border text-xs font-mono ${
              testStatus.isError
                ? 'bg-rose-950/40 border-rose-500/50 text-rose-300'
                : 'bg-emerald-950/40 border-emerald-500/50 text-emerald-300'
            }`}
          >
            <div className="flex items-center gap-2">
              {testStatus.loading ? (
                <span className="h-3.5 w-3.5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
              ) : testStatus.isError ? (
                <AlertCircle className="h-4 w-4 text-rose-400 shrink-0" />
              ) : (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              )}
              <span>{testStatus.message}</span>
            </div>
          </div>
        )}

        {/* Action Buttons */}
        <div className="flex items-center justify-between pt-2 border-t border-zinc-800">
          <button
            type="button"
            onClick={handleTestToken}
            disabled={testStatus.loading || !tokenInput.trim()}
            className="px-3 py-1.5 rounded border border-zinc-700 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-bold text-xs disabled:opacity-50"
          >
            {testStatus.loading ? 'Validando...' : 'Testar Token'}
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded border border-zinc-800 text-zinc-400 hover:text-white text-xs"
            >
              Cancelar
            </button>

            <button
              type="button"
              onClick={handleSave}
              className={`px-5 py-1.5 rounded font-bold text-xs flex items-center gap-2 transition-all ${
                savedSuccess
                  ? 'bg-emerald-500 text-zinc-950'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg'
              }`}
            >
              <Lock className="h-3.5 w-3.5" />
              <span>{savedSuccess ? 'Token Salvo com Sucesso!' : 'Salvar & Liberar PRs'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
