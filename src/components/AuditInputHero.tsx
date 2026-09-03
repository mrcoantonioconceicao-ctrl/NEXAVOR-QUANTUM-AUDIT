import React, { useState, useMemo, useEffect } from 'react';
import {
  Github,
  Code2,
  ArrowRight,
  Database,
  Layers,
  Key,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  GitPullRequest,
  FolderGit2,
  Sparkles,
} from 'lucide-react';
import { BENCHMARK_CASES } from '../domain/benchmarks.ts';
import { getStoredGitHubToken, setStoredGitHubToken } from '../services/tokenStorage.ts';

interface AuditInputHeroProps {
  onStartAuditWithUrl: (
    url: string,
    token?: string,
    scope?: 'FULL_REPO' | 'PULL_REQUEST',
    pullNumber?: number
  ) => void;
  onStartAuditWithCustomCode: (repoName: string, fileName: string, code: string) => void;
  isAuditing: boolean;
  lastErrorMessage?: string | null;
  onClearError?: () => void;
}

const LANGUAGE_TEMPLATES: Record<string, { fileName: string; repoName: string; code: string }> = {
  Rust: {
    fileName: 'src/lib.rs',
    repoName: 'rust-security-legacy',
    code: `// Código Legado Rust com vulnerabilidade de memória e concorrência
use std::mem;

pub struct UnsafeBuffer {
    ptr: *mut u8,
    len: usize,
}

impl UnsafeBuffer {
    pub fn allocate_raw(size: usize) -> Self {
        // VULNERABILIDADE: Leitura de memória desinicializada
        let raw_chunk: [u8; 1024] = unsafe { mem::uninitialized() };
        let mut v = raw_chunk.to_vec();
        let ptr = v.as_mut_ptr();
        mem::forget(v);

        UnsafeBuffer { ptr, len: size }
    }

    pub unsafe fn write_offset(&self, offset: usize, val: u8) {
        *self.ptr.add(offset) = val;
    }
}

// Insegurança: Panic em Drop
impl Drop for UnsafeBuffer {
    fn drop(&mut self) {
        if self.len > 10000 {
            panic!("Tamanho inválido!");
        }
    }
}`,
  },
  Python: {
    fileName: 'app/main.py',
    repoName: 'python-ai-microservice',
    code: `# FastAPI / PyTorch Gateway
import pickle
import os
import hashlib
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/api/v1/load-weights")
async def load_weights(request: Request):
    # VULNERABILIDADE CRÍTICA: Desserialização RCE via pickle
    payload = await request.body()
    weights = pickle.loads(payload)
    return {"loaded": len(weights)}

@app.get("/api/v1/system-diag")
def system_diagnostics(cmd_param: str):
    # VULNERABILIDADE: Injeção de Comando no Sistema Operacional
    os.system(f"nvidia-smi {cmd_param}")
    return {"status": "DISPATCHED"}

def verify_token(incoming: str, secret: str) -> bool:
    # VULNERABILIDADE: Timing Attack e Hash Obsoleto MD5
    h1 = hashlib.md5(incoming.encode()).hexdigest()
    h2 = hashlib.md5(secret.encode()).hexdigest()
    return h1 == h2`,
  },
  TypeScript: {
    fileName: 'src/server.ts',
    repoName: 'node-ts-auth-service',
    code: `import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';

const app = express();

// VULNERABILIDADE: Bypass com jwt.decode sem validar assinatura
export function verifySession(token: string) {
  return jwt.decode(token);
}

// VULNERABILIDADE: Poluição de Protótipo (Prototype Pollution)
export function mergeConfig(target: any, source: any) {
  for (const key of Object.keys(source)) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      mergeConfig(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// VULNERABILIDADE: Buffer.allocUnsafe vaza dados de memória heap
export function createSessionNonce(len: number) {
  return Buffer.allocUnsafe(len);
}`,
  },
  Go: {
    fileName: 'main.go',
    repoName: 'golang-distributed-node',
    code: `package main

import (
	"database/sql"
	"fmt"
	"sync"
	"unsafe"
)

type ClusterRegistry struct {
	// VULNERABILIDADE: Data race em map sem Mutex
	nodes map[string]string
	wg    sync.WaitGroup
}

func (c *ClusterRegistry) AddNodeAsync(id, addr string) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.nodes[id] = addr // Fatal crash concorrente
	}()
}

// VULNERABILIDADE: Injeção de SQL via fmt.Sprintf
func QueryTenantData(db *sql.DB, tenantID string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT * FROM secrets WHERE tenant = '%s'", tenantID)
	return db.Query(query)
}`,
  },
  'C/C++': {
    fileName: 'src/daemon.cpp',
    repoName: 'cpp-packet-engine',
    code: `#include <iostream>
#include <cstring>
#include <cstdio>

// VULNERABILIDADE: Buffer Overflow em pilha
void process_network_packet(const char* raw_stream) {
    char stack_buf[64];
    strcpy(stack_buf, raw_stream); // Sobrescreve frame pointer e RIP
    
    // VULNERABILIDADE: Format string vulnerability
    printf(stack_buf);
}

// VULNERABILIDADE: Use-After-Free
void free_and_use(char* ptr) {
    free(ptr);
    std::cout << "Data: " << ptr[0] << std::endl;
}`,
  },
  Solidity: {
    fileName: 'contracts/StakingVault.sol',
    repoName: 'solidity-defi-vault',
    code: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StakingVault {
    mapping(address => uint256) public balances;

    // VULNERABILIDADE CRÍTICA: Reentrância Clássica (Transferência antes de atualizar saldo)
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Sem saldo");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Falha na transferencia");

        balances[msg.sender] = 0;
    }

    // VULNERABILIDADE: Autenticação via tx.origin vulnerável a Phishing
    function emergencyDrain(address payable recipient) public {
        require(tx.origin == msg.sender, "Nao autorizado");
        recipient.transfer(address(this).balance);
    }
}`,
  },
};

const POPULAR_REAL_GITHUB_REPOS = [
  { name: 'pagamentos-inteligentes', fullName: 'mrcoantonioconceicao-ctrl/pagamentos-inteligentes', lang: 'Rust/Solana', desc: 'Smart Contract de Pagamentos Inteligentes (Anchor)' },
  { name: 'tokio', fullName: 'tokio-rs/tokio', lang: 'Rust', desc: 'Runtime assíncrono para Rust' },
  { name: 'hyper', fullName: 'hyperium/hyper', lang: 'Rust', desc: 'Biblioteca HTTP de alta performance em Rust' },
  { name: 'express', fullName: 'expressjs/express', lang: 'JavaScript', desc: 'Framework web para Node.js' },
  { name: 'fastapi', fullName: 'tiangolo/fastapi', lang: 'Python', desc: 'Framework moderno de APIs em Python' },
  { name: 'solana-programs', fullName: 'solana-labs/solana-program-library', lang: 'Rust', desc: 'Contratos e programas on-chain Solana' },
  { name: 'gin', fullName: 'gin-gonic/gin', lang: 'Go', desc: 'Framework HTTP de alta performance em Go' },
];

export const AuditInputHero: React.FC<AuditInputHeroProps> = ({
  onStartAuditWithUrl,
  onStartAuditWithCustomCode,
  isAuditing,
  lastErrorMessage,
  onClearError,
}) => {
  const [inputMode, setInputMode] = useState<'url' | 'code'>('url');
  const [auditScope, setAuditScope] = useState<'FULL_REPO' | 'PULL_REQUEST'>('FULL_REPO');
  const [githubUrl, setGithubUrl] = useState('');
  const [prNumberInput, setPrNumberInput] = useState('');
  const [githubToken, setGithubToken] = useState<string>(() => getStoredGitHubToken());
  const [showTokenInput, setShowTokenInput] = useState<boolean>(() => Boolean(getStoredGitHubToken()));

  const handleTokenChange = (t: string) => {
    setGithubToken(t);
    setStoredGitHubToken(t);
  };
  const [selectedLang, setSelectedLang] = useState<string>('Rust');
  const [customRepoName, setCustomRepoName] = useState(LANGUAGE_TEMPLATES.Rust.repoName);
  const [customFileName, setCustomFileName] = useState(LANGUAGE_TEMPLATES.Rust.fileName);
  const [customCode, setCustomCode] = useState(LANGUAGE_TEMPLATES.Rust.code);

  // Auto-detect Pull Request URL
  useEffect(() => {
    if (githubUrl.includes('/pull/') || githubUrl.includes('/pulls/')) {
      setAuditScope('PULL_REQUEST');
    }
  }, [githubUrl]);

  // Live parsed repository detection
  const parsedRepoPreview = useMemo(() => {
    let raw = githubUrl.trim();
    if (!raw) return null;

    // Normalize backslashes from Windows paths or typing
    raw = raw.replace(/\\+/g, '/');

    if (raw.startsWith('git@github.com:')) {
      raw = raw.replace('git@github.com:', '').replace(/\.git$/, '');
      const p = raw.split('/').filter(Boolean);
      if (p.length >= 2) return { owner: p[0], repo: p.slice(1).join('/') };
    }

    raw = raw
      .replace(/^https?:\/\//i, '')
      .replace(/^www\./i, '')
      .replace(/^github\.com\//i, '')
      .replace(/^raw\.githubusercontent\.com\//i, '')
      .replace(/\.git$/, '')
      .split('?')[0]
      .split('#')[0]
      .replace(/[;,.]*$/, '');

    const parts = raw.split('/').filter(Boolean);
    if (parts.length >= 2) {
      let pullNum: number | undefined;
      if (parts.length >= 4 && (parts[2] === 'pull' || parts[2] === 'pulls')) {
        pullNum = parseInt(parts[3], 10);
      }
      return { owner: parts[0], repo: parts.slice(1).join('/'), pullNum };
    }
    return null;
  }, [githubUrl]);

  const handleLanguageChange = (lang: string) => {
    setSelectedLang(lang);
    const tmpl = LANGUAGE_TEMPLATES[lang];
    if (tmpl) {
      setCustomRepoName(tmpl.repoName);
      setCustomFileName(tmpl.fileName);
      setCustomCode(tmpl.code);
    }
  };

  const handleAuditSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onClearError?.();
    if (inputMode === 'url') {
      if (!githubUrl.trim()) return;
      const parsedPr = prNumberInput.trim() ? parseInt(prNumberInput.replace(/\D/g, ''), 10) : undefined;
      onStartAuditWithUrl(
        githubUrl.trim(),
        githubToken.trim() || undefined,
        auditScope,
        parsedPr || parsedRepoPreview?.pullNum
      );
    } else {
      if (!customCode.trim()) return;
      onStartAuditWithCustomCode(customRepoName.trim(), customFileName.trim(), customCode);
    }
  };

  const handleSelectBenchmark = (benchId: string) => {
    onClearError?.();
    const found = BENCHMARK_CASES.find((b) => b.id === benchId);
    if (found) {
      const mainFile =
        found.files.find(
          (f) =>
            !f.path.endsWith('.toml') &&
            !f.path.endsWith('.json') &&
            !f.path.endsWith('.txt') &&
            !f.path.endsWith('.mod')
        ) || found.files[0];

      const repoName = found.repo.name;
      const fileName = mainFile?.path || 'src/lib.rs';
      const code = mainFile?.content || '';

      setCustomRepoName(repoName);
      setCustomFileName(fileName);
      setCustomCode(code);
      setSelectedLang(found.language || 'Rust');
      setInputMode('code');
      onStartAuditWithCustomCode(repoName, fileName, code);
    }
  };

  const handleSelectRealRepo = (repoFullName: string, forceScope?: 'FULL_REPO' | 'PULL_REQUEST') => {
    onClearError?.();
    const fullUrl = `https://github.com/${repoFullName}`;
    setGithubUrl(fullUrl);
    setInputMode('url');
    const scopeToUse = forceScope || auditScope;
    setAuditScope(scopeToUse);
    onStartAuditWithUrl(fullUrl, undefined, scopeToUse);
  };

  return (
    <div className="w-full bg-zinc-950 border-b border-zinc-800 py-8 px-4 sm:px-6">
      <div className="max-w-5xl mx-auto space-y-6">
        {/* Title & Metadata Badge */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center gap-2 rounded border border-zinc-800 bg-zinc-900/60 px-3 py-1 text-[10px] font-mono uppercase tracking-widest text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
            <span>v2.5.0-POLYGLOT | ALL-LANGUAGES REPOSITORY INGESTION & AUDIT</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-light tracking-tight text-white font-mono uppercase">
            Auditoria Forense de Repositórios Multi-Linguagem
          </h1>
          <p className="text-xs text-zinc-400 max-w-2xl mx-auto leading-relaxed">
            Auditoria pericial em <strong>todas as linguagens</strong> (Rust, Python, TypeScript, JavaScript, Go, C/C++, Java, Solidity, PHP, C#). Suporte completo para <strong>Auditoria Completa do Repositório</strong> ou <strong>Auditoria Focada em Pull Request</strong>.
          </p>

          {/* Supported Language Chips */}
          <div className="flex flex-wrap items-center justify-center gap-1.5 pt-1">
            {['Rust', 'Python', 'TypeScript', 'JavaScript', 'Go', 'C / C++', 'Java', 'Solidity', 'C#', 'PHP'].map((lang) => (
              <span
                key={lang}
                className="px-2 py-0.5 rounded text-[10px] font-mono bg-zinc-900 border border-zinc-800 text-zinc-400"
              >
                {lang}
              </span>
            ))}
          </div>
        </div>

        {/* Input Mode Selector */}
        <div className="flex justify-center">
          <div className="inline-flex rounded bg-zinc-900 p-1 border border-zinc-800">
            <button
              type="button"
              onClick={() => setInputMode('url')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded text-[11px] font-mono uppercase tracking-wider font-bold transition-colors ${
                inputMode === 'url'
                  ? 'bg-zinc-800 text-emerald-400 border border-zinc-700 shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Github className="h-3.5 w-3.5" />
              <span>Repositório GitHub (URL)</span>
            </button>
            <button
              type="button"
              onClick={() => setInputMode('code')}
              className={`flex items-center gap-2 px-3.5 py-1.5 rounded text-[11px] font-mono uppercase tracking-wider font-bold transition-colors ${
                inputMode === 'code'
                  ? 'bg-zinc-800 text-emerald-400 border border-zinc-700 shadow-xs'
                  : 'text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Code2 className="h-3.5 w-3.5" />
              <span>Editor de Código Manual</span>
            </button>
          </div>
        </div>

        {/* Error Notification Banner if repository failed to read */}
        {lastErrorMessage && (
          <div className="max-w-3xl mx-auto p-4 rounded border border-rose-800/80 bg-rose-950/40 text-rose-200 text-xs font-mono space-y-2">
            <div className="flex items-start gap-2.5">
              <AlertCircle className="h-4 w-4 text-rose-400 shrink-0 mt-0.5" />
              <div className="space-y-1 flex-1">
                <div className="font-bold text-rose-300">Falha ao ler repositório:</div>
                <div className="text-zinc-300 font-sans leading-relaxed">{lastErrorMessage}</div>
              </div>
            </div>
            <div className="pt-2 border-t border-rose-900/40 flex flex-wrap items-center gap-2 text-[11px]">
              <span className="text-zinc-400">Sugestões:</span>
              <button
                type="button"
                onClick={() => setShowTokenInput(true)}
                className="px-2 py-1 rounded bg-rose-900/60 border border-rose-700 text-rose-200 hover:bg-rose-800 transition-colors"
              >
                + Adicionar Token do GitHub (PAT)
              </button>
              <button
                type="button"
                onClick={() => setInputMode('code')}
                className="px-2 py-1 rounded bg-zinc-800 border border-zinc-700 text-zinc-200 hover:bg-zinc-700 transition-colors"
              >
                Colar código no Editor Manual
              </button>
            </div>
          </div>
        )}

        {/* Input Form */}
        <form onSubmit={handleAuditSubmit} className="space-y-4">
          {inputMode === 'url' ? (
            <div className="max-w-3xl mx-auto space-y-4">
              {/* Escopo de Auditoria: Completa vs Pull Request */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* 1. Auditoria Completa */}
                <button
                  type="button"
                  onClick={() => setAuditScope('FULL_REPO')}
                  className={`p-3.5 rounded-lg border text-left transition-all ${
                    auditScope === 'FULL_REPO'
                      ? 'bg-emerald-950/30 border-emerald-500/60 ring-1 ring-emerald-500/30 shadow-xs'
                      : 'bg-zinc-900/60 border-zinc-800 hover:border-zinc-700 text-zinc-400 hover:text-zinc-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <FolderGit2
                        className={`h-4 w-4 ${auditScope === 'FULL_REPO' ? 'text-emerald-400' : 'text-zinc-500'}`}
                      />
                      <span
                        className={`text-xs font-mono font-bold uppercase tracking-wider ${
                          auditScope === 'FULL_REPO' ? 'text-emerald-300' : 'text-zinc-300'
                        }`}
                      >
                        Auditoria Completa
                      </span>
                    </div>
                    {auditScope === 'FULL_REPO' && (
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    )}
                  </div>
                  <p className="text-[11px] text-zinc-400 mt-1.5 font-sans leading-relaxed">
                    Varredura total em 100% dos arquivos, árvores de dependência, crates e arquitetura da branch principal.
                  </p>
                </button>

                {/* 2. Apenas Pull Request */}
                <button
                  type="button"
                  onClick={() => setAuditScope('PULL_REQUEST')}
                  className={`p-3.5 rounded-lg border text-left transition-all ${
                    auditScope === 'PULL_REQUEST'
                      ? 'bg-emerald-950/30 border-emerald-500/60 ring-1 ring-emerald-500/30 shadow-xs'
                      : 'bg-zinc-900/60 border-zinc-800 hover:border-zinc-700 text-zinc-400 hover:text-zinc-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <GitPullRequest
                        className={`h-4 w-4 ${auditScope === 'PULL_REQUEST' ? 'text-emerald-400' : 'text-zinc-500'}`}
                      />
                      <span
                        className={`text-xs font-mono font-bold uppercase tracking-wider ${
                          auditScope === 'PULL_REQUEST' ? 'text-emerald-300' : 'text-zinc-300'
                        }`}
                      >
                        Apenas Pull Request
                      </span>
                    </div>
                    {auditScope === 'PULL_REQUEST' && (
                      <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    )}
                  </div>
                  <p className="text-[11px] text-zinc-400 mt-1.5 font-sans leading-relaxed">
                    Inspeção pericial focada exclusivamente no diff e arquivos alterados no PR para aprovação/bloqueio.
                  </p>
                </button>
              </div>

              {/* Main URL & PR input */}
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 flex items-center pl-3.5 pointer-events-none text-zinc-500">
                    {auditScope === 'PULL_REQUEST' ? (
                      <GitPullRequest className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <Github className="h-4 w-4" />
                    )}
                  </div>
                  <input
                    type="text"
                    value={githubUrl}
                    onChange={(e) => {
                      setGithubUrl(e.target.value);
                      onClearError?.();
                    }}
                    placeholder={
                      auditScope === 'PULL_REQUEST'
                        ? 'https://github.com/usuario/repositorio/pull/123 ou usuario/repositorio'
                        : 'https://github.com/usuario/repositorio (ou usuario/repositorio)'
                    }
                    disabled={isAuditing}
                    className="w-full pl-10 pr-28 py-2.5 bg-zinc-900 border border-zinc-800 rounded text-xs text-emerald-400 placeholder-zinc-600 focus:outline-none focus:border-emerald-500 font-mono transition-colors"
                  />
                  <div className="absolute right-3 top-2.5 text-zinc-500 font-mono text-[10px] uppercase tracking-wider pointer-events-none">
                    {auditScope === 'PULL_REQUEST' ? 'PR_MODE' : 'ANY_REPO'}
                  </div>
                </div>

                {auditScope === 'PULL_REQUEST' && (
                  <div className="relative w-full sm:w-28">
                    <input
                      type="text"
                      value={prNumberInput}
                      onChange={(e) => setPrNumberInput(e.target.value)}
                      placeholder="PR # (ex: 42)"
                      disabled={isAuditing}
                      className="w-full px-3 py-2.5 bg-zinc-900 border border-zinc-800 rounded text-xs text-emerald-300 placeholder-zinc-600 focus:outline-none focus:border-emerald-500 font-mono text-center"
                    />
                  </div>
                )}

                <button
                  type="submit"
                  disabled={isAuditing || !githubUrl.trim()}
                  className="flex items-center justify-center gap-2 px-5 py-2.5 bg-zinc-100 hover:bg-white text-zinc-950 text-[11px] font-mono font-bold uppercase tracking-widest rounded transition-colors shadow-xs disabled:opacity-50 shrink-0"
                >
                  {isAuditing ? (
                    <>
                      <span className="h-3.5 w-3.5 border-2 border-zinc-950 border-t-transparent rounded-full animate-spin" />
                      <span>Auditando {auditScope === 'PULL_REQUEST' ? 'PR' : 'Repo'}...</span>
                    </>
                  ) : (
                    <>
                      <span>{auditScope === 'PULL_REQUEST' ? 'Auditar PR' : 'Auditar Repo'}</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </>
                  )}
                </button>
              </div>

              {/* Target Repository Detection & Token Toggle */}
              <div className="flex flex-wrap items-center justify-between gap-2 px-1 text-[11px] font-mono">
                <div>
                  {parsedRepoPreview ? (
                    <span className="text-emerald-400 flex items-center gap-1.5">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Alvo: <strong>{parsedRepoPreview.owner}</strong> / <strong>{parsedRepoPreview.repo}</strong>
                      {parsedRepoPreview.pullNum && (
                        <span className="ml-1 px-1.5 py-0.2 rounded bg-emerald-950 border border-emerald-500/40 text-[10px] font-bold">
                          PR #{parsedRepoPreview.pullNum}
                        </span>
                      )}
                      <span className="text-zinc-500 font-normal">
                        ({auditScope === 'PULL_REQUEST' ? 'Modo Pull Request' : 'Auditoria Completa'})
                      </span>
                    </span>
                  ) : (
                    <span className="text-zinc-500">
                      {auditScope === 'PULL_REQUEST'
                        ? 'Cole a URL do PR ou o repositório com o número do PR'
                        : 'Formatos aceitos: https://github.com/user/repo ou user/repo'}
                    </span>
                  )}
                </div>

                <button
                  type="button"
                  onClick={() => setShowTokenInput(!showTokenInput)}
                  className="text-zinc-400 hover:text-emerald-400 flex items-center gap-1 transition-colors"
                >
                  <Key className="h-3 w-3" />
                  <span>{showTokenInput ? 'Ocultar Token PAT' : 'Repositório Privado / Token PAT (Opcional)'}</span>
                </button>
              </div>

              {/* Optional GitHub Token Input */}
              {showTokenInput && (
                <div className="p-3 rounded border border-zinc-800 bg-zinc-900/70 space-y-2">
                  <div className="flex items-center justify-between text-xs text-zinc-400 font-mono">
                    <span className="flex items-center gap-1.5 text-zinc-300 font-bold">
                      <Key className="h-3.5 w-3.5 text-emerald-400" />
                      GitHub Personal Access Token (PAT)
                    </span>
                    <span className="text-[10px] text-zinc-500">Privacidade 100% Protegida (TLS Server-Side)</span>
                  </div>
                  <input
                    type="password"
                    value={githubToken}
                    onChange={(e) => handleTokenChange(e.target.value)}
                    placeholder="ghp_xxxxxxxxxxxxxxxxxxxx (necessário para repositórios privados e criação de Pull Requests)"
                    className="w-full px-3 py-2 bg-zinc-950 border border-zinc-800 rounded text-xs text-zinc-200 font-mono placeholder-zinc-700 focus:outline-none focus:border-emerald-500"
                  />
                </div>
              )}
            </div>
          ) : (
            <div className="max-w-3xl mx-auto space-y-3">
              {/* Language Template Selector */}
              <div className="flex items-center gap-2 overflow-x-auto pb-1">
                <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-wider shrink-0 flex items-center gap-1">
                  <Layers className="h-3 w-3 text-emerald-400" />
                  Templates:
                </span>
                {Object.keys(LANGUAGE_TEMPLATES).map((lang) => (
                  <button
                    key={lang}
                    type="button"
                    onClick={() => handleLanguageChange(lang)}
                    className={`px-2.5 py-1 rounded text-[11px] font-mono tracking-wider transition-colors shrink-0 ${
                      selectedLang === lang
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/50'
                        : 'bg-zinc-900 text-zinc-400 border border-zinc-800 hover:text-zinc-200'
                    }`}
                  >
                    {lang}
                  </button>
                ))}
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <input
                  type="text"
                  value={customRepoName}
                  onChange={(e) => setCustomRepoName(e.target.value)}
                  placeholder="Nome do Projeto"
                  className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded text-xs text-zinc-200 font-mono focus:outline-none focus:border-emerald-500"
                />
                <input
                  type="text"
                  value={customFileName}
                  onChange={(e) => setCustomFileName(e.target.value)}
                  placeholder="Caminho do arquivo (ex: src/lib.rs, app.py, server.ts)"
                  className="px-3 py-2 bg-zinc-900 border border-zinc-800 rounded text-xs text-zinc-200 font-mono focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div className="relative rounded border border-zinc-800 bg-zinc-900 overflow-hidden">
                <div className="flex items-center justify-between px-3 py-1.5 bg-zinc-900/80 border-b border-zinc-800 text-[10px] text-zinc-400 font-mono uppercase tracking-wider">
                  <span>Source Code ({selectedLang})</span>
                  <span>{customCode.split('\n').length} linhas</span>
                </div>
                <textarea
                  value={customCode}
                  onChange={(e) => setCustomCode(e.target.value)}
                  rows={10}
                  spellCheck={false}
                  placeholder="// Cole o código fonte para auditoria..."
                  className="w-full p-3 bg-zinc-950 font-mono text-xs text-emerald-300 placeholder-zinc-600 focus:outline-none focus:ring-1 focus:ring-emerald-500 resize-y leading-relaxed"
                />
              </div>
              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isAuditing || !customCode.trim()}
                  className="flex items-center gap-2 px-5 py-2 bg-zinc-100 hover:bg-white text-zinc-950 text-[11px] font-mono font-bold uppercase tracking-widest rounded transition-colors shadow-xs disabled:opacity-50"
                >
                  <span>Auditar Código</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </form>

        {/* 1-Click Real GitHub Repositories */}
        <div className="border-t border-zinc-800/80 pt-5 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Github className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-300">
                Repositórios Públicos Reais no GitHub (Ingestão Git REST API):
              </span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-zinc-500">
                Auditar como:
              </span>
              <button
                type="button"
                onClick={() => setAuditScope('FULL_REPO')}
                className={`text-[10px] font-mono px-2 py-0.5 rounded transition-colors ${
                  auditScope === 'FULL_REPO'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                Repo Completo
              </button>
              <button
                type="button"
                onClick={() => setAuditScope('PULL_REQUEST')}
                className={`text-[10px] font-mono px-2 py-0.5 rounded transition-colors ${
                  auditScope === 'PULL_REQUEST'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-bold'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                Pull Request
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
            {POPULAR_REAL_GITHUB_REPOS.map((r) => (
              <button
                key={r.fullName}
                type="button"
                onClick={() => handleSelectRealRepo(r.fullName)}
                className="p-2.5 rounded border border-zinc-800 bg-zinc-900/40 hover:bg-zinc-850 hover:border-zinc-700 text-left transition-all group flex flex-col justify-between"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-emerald-400 font-bold uppercase">
                    {r.lang}
                  </span>
                  <ExternalLink className="h-3 w-3 text-zinc-600 group-hover:text-zinc-400" />
                </div>
                <div className="mt-2 text-xs font-mono font-bold text-zinc-200 truncate group-hover:text-emerald-300">
                  {r.name}
                </div>
                <div className="text-[10px] text-zinc-500 truncate mt-0.5">
                  {r.fullName}
                </div>
              </button>
            ))}
          </div>

          {/* Forensic Study Cases loaded directly into Code Editor */}
          <div className="pt-2">
            <div className="flex items-center gap-2 mb-2">
              <Code2 className="h-3.5 w-3.5 text-blue-400" />
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-zinc-400">
                Amostras de Vulnerabilidades para Auditoria AST (Editor Manual):
              </span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2">
              {BENCHMARK_CASES.map((b) => (
                <button
                  key={b.id}
                  type="button"
                  onClick={() => handleSelectBenchmark(b.id)}
                  className="p-2 rounded border border-zinc-800/80 bg-zinc-900/20 hover:bg-zinc-850 hover:border-zinc-700 text-left transition-all group flex flex-col justify-between"
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-400 group-hover:text-blue-300 font-semibold uppercase">
                      {b.language || 'Polyglot'}
                    </span>
                  </div>
                  <div className="mt-1.5 text-[11px] font-mono font-medium text-zinc-300 truncate group-hover:text-zinc-100">
                    {b.name.split(' (')[0]}
                  </div>
                  <div className="text-[9px] text-zinc-500 truncate mt-0.5">
                    {b.category}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
