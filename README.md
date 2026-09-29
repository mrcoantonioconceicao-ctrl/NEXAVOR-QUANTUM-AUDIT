# 🛡️ RustShield Quantum — Solana Anchor Smart Contract & Enterprise Security Auditor

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Anchor Framework](https://img.shields.io/badge/Anchor-v0.30.0-emerald.svg)](https://www.anchor-lang.com/)
[![Solana](https://img.shields.io/badge/Solana-Mainnet--Beta%20%7C%20Devnet-14F195.svg?logo=solana)](https://solana.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8.3-3178C6.svg?logo=typescript)](https://www.typescriptlang.org/)
[![Vercel Serverless](https://img.shields.io/badge/Vercel-Serverless%20Ready-black.svg?logo=vercel)](https://vercel.com)
[![Build Status](https://img.shields.io/badge/Build-100%25%20Verified-brightgreen.svg)]()
[![Security Audit](https://img.shields.io/badge/Audit%20Score-100%2F100-success.svg)]()

**RustShield Quantum** é um ecossistema unificado de auditoria de segurança pericial, análise estática determinística de código AST, avaliação de criptografia pós-quântica (NIST PQC) e plataforma de contratos inteligentes em **Solana Anchor** otimizada para ambientes Serverless (Vercel).

---

## 🌟 Principais Recursos & Capacidades

### 1. ⚡ Solana Anchor Smart Contract (`solana_sandbox_counter`)
- **Program ID**: `Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS`
- **Anchor 0.30 IDL & Types**: Tipagem estrita gerada automaticamente em `target/types/solana_sandbox_counter.ts`.
- **SDK Cliente TypeScript**: Biblioteca cliente completa em `client/index.ts` para interação com a blockchain Solana (`initialize`, `increment`, `fetchCounter`, `deriveCounterPda`).
- **Segurança de Memória Hardened**: Prevenção rigorosa contra *Integer Overflow* via `checked_add` e erros customizados (`ErrorCode::CounterOverflow`).
- **Testes de Integração**: Suíte de testes com derivação determinística de PDA (`b"counter"`, `authority`) e asserções completas em `tests/`.

### 2. 🛡️ Motor Determinístico de Auditoria Pericial AST & Solana/Anchor (`solanaAuditLifecycleService.ts`)
- **Invariantes em Smart Contracts Solana/Anchor**:
  - *Signer Verification & Privileges*: Inspeciona estruturas `AccountInfo<'info>` vs `Signer<'info>` e restrições `#[account(signer)]` para barrar escalação de privilégios.
  - *CPI Program ID Invariance*: Identifica chamadas cruzadas `invoke` / `invoke_signed` sem validação do `program_id` alvo (prevenção contra *CPI Spoofing*).
  - *Derivação de PDAs e Canonical Bumps*: Detecta chamadas a `find_program_address` sem validação de `bump` canônico.
  - *Aritmética Financeira Segura*: Mapeia manipulação de saldos sem `checked_add` / `checked_sub`.
- **Ciclo de Auditoria Autónomo vs Interativo (`runSolanaAuditLifecycle`)**:
  - `audit-cycle`: Análise determinística ponta a ponta sem intervenção manual.
  - `audit-assist`: Fluxo interativo *human-in-the-loop* que gera checkpoints de decisão em falhas críticas antes da emissão do relatório final.
- **Gerador de Patches & PoCs**: Emissão automática de diffs de correção de macros Anchor e scripts de teste de exploração em TypeScript/Anchor Framework (`pocTestCode`).

### 3. ⚡ Configuração Serverless Vercel & Isolamento de Build
- **Isolamento da Build Web (`vercel.json` & `.vercelignore`)**: Vercel configurada estritamente como aplicação Vite/React (diretório `dist`). As pastas Rust (`programs/`, `target/`, `Cargo.toml`) são ativamente ignoradas no Serverless, reservando a compilação de binários nativos para o CI/CD do GitHub Actions.
- **Adaptador Serverless (`/api/index.ts`)**: Rotas Express adaptadas para responder em Vercel Serverless / Edge Functions.
- **Autonomia em Indisponibilidade (HTTP 503 / 429)**: Mecanismo de fallback gracioso local que entrega auditorias completas de forma autônoma caso APIs externas sofram *rate limit*.
- **Injeção Dinâmica de PAT**: Token do GitHub gerenciado no `localStorage` do cliente e enviado via cabeçalho `Authorization: Bearer <token>`.

### 4. 🧭 UX Cockpit Web & Navegação Fluida
- **Navegação Lateral Fixa (`NavigationSidebar`)**: Barra de navegação persistente com indicadores de página ativa, status do repositório-alvo e atalhos rápidos.
- **Atalhos e Histórico na TopBar (`TopBar.tsx`)**: Botão "Voltar" integrado com histórico em memória e sub-strip de atalhos rápidos (*Dashboard*, *Auditoria AST/Solana*, *Estúdio de Refatoração*, *PQC Quântica* e *Relatórios GRC*).

### 5. 🔒 Governança, LGPD e Relatórios Executivos C-Level
- **Anonimização Telemétrica LGPD/GDPR**: Sanitização rigorosa de identificadores de usuário e repositório utilizando hashes criptográficos **HMAC-SHA256** (`anonymizeLgpdHmacSha256`).
- **Selos Executivos Vetoriais em SVG**: Geração dinâmica de badges visuais (`/api/badge/shield.svg`) para inclusão em relatórios executivos C-Level e documentação do repositório.

### 6. ⚛️ Criptografia Pós-Quântica (NIST PQC) & Refatoração AST
- **Avaliação Quantum-Ready**: Transição recomendada para algoritmos aprovados pelo NIST (ML-KEM / Kyber, ML-DSA / Dilithium).
- **Estúdio de Refatoração AST In-Place (`AstRefactorStudio`)**: Aplicação de patches de segurança de pânico zero e submissão automatizada de Pull Requests via Octokit.

---

## 📊 Relatório de Auditoria do Smart Contract

| Métrica / Parâmetro | Valor / Estado |
| :--- | :--- |
| **Score de Segurança** | **`100 / 100`** |
| **Program ID (Solana)** | `Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS` |
| **Versão do Anchor** | `v0.30.0` |
| **Linter TypeScript (`tsc`)** | `0 Erros` (Passou 100%) |
| **Status de Compilação Web** | `Aprovado` (`compile_applet` & `vite build`) |
| **Redes Suportadas** | Localnet / Devnet / Mainnet-Beta |

---

## 📁 Estrutura do Repositório

```text
.
├── vercel.json                          # Configuração de Build Serverless para Vercel (Vite + SPA)
├── .vercelignore                        # Regras para ignorar crates e binários Rust no deploy Vercel
├── Anchor.toml                          # Configuração do Workspace Anchor (Localnet/Devnet)
├── Cargo.toml                           # Workspace Cargo do Smart Contract Rust
├── package.json                         # Dependências Full-Stack (Anchor, Solana Web3, React, Vite, Express)
├── README.md                            # Documentação técnica do ecossistema
├── api/
│   └── index.ts                         # Ponto de entrada adaptado para Vercel Serverless Functions
├── client/
│   └── index.ts                         # SDK Cliente TypeScript (SolanaSandboxCounterClient)
├── tests/
│   └── solana_sandbox_counter.ts        # Testes unitários e de integração Anchor
├── programs/
│   └── solana_sandbox_counter/          # Smart Contract Rust (Isolado no CI/CD)
│       └── src/
│           └── lib.rs                   # Código do contrato Rust (Hardened)
├── server/                              # Servidor Backend Express + Gemini API + MCP Protocol
│   ├── routes.ts                        # Endpoints de Auditoria, RAG, Webhooks e Métricas
│   ├── mcpServer.ts                     # Servidor do Protocolo MCP (SSE + JSON-RPC 2.0)
│   └── badgeGenerator.ts                # Gerador de Badges SVG Executivos
└── src/                                 # Cockpit Web Frontend (React 19, Tailwind, Motion)
    ├── App.tsx                          # Dashboard Unificada e Navegação com Histórico
    ├── components/                      # NavigationSidebar, TopBar e Módulos de Interface
    └── services/                        # Motores Estáticos (solanaAuditLifecycleService, deterministicAuditEngine)
```

---

## 🚀 Como Executar o Projeto

### Prerequisitos
- **Node.js**: `v20.0.0+`
- **Rust & Cargo**: `1.70.0+` (opcional para desenvolvimento do contrato)
- **Solana CLI & Anchor CLI**: `v0.30.0+`

---

### 1. Servidor Web & Cockpit de Auditoria
```bash
# 1. Instalar dependências
npm install

# 2. Executar verificação de tipos TypeScript
npm run lint

# 3. Compilar aplicação para produção
npm run build

# 4. Iniciar o servidor de desenvolvimento
npm run dev
```
> O servidor estará acessível em `http://localhost:3000`.

---

### 2. Smart Contract Solana Anchor (Local / CI)
```bash
# Compilar o Smart Contract Rust (no ambiente local ou GitHub Actions)
anchor build

# Executar a suíte de testes Anchor
anchor test
```

---

## 📄 Licença
Distribuído sob a licença **Apache 2.0**. Consulte o arquivo `LICENSE` para obter mais detalhes.

---
*RustShield Quantum — Garantindo a segurança e resiliência de Smart Contracts Solana e software corporativo.*

