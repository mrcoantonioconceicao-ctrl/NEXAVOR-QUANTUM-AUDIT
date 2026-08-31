# 🛡️ NEXAVOR-QUANTUM-AUDIT (RustShield Quantum v2.0)
#### Enterprise DevSecOps, GRC Governance, Software Supply Chain, Model Context Protocol (MCP) & Post-Quantum Cryptography Suite

[![CI/CD Security Gate](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT/actions/workflows/ci.yml/badge.svg)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT/actions)
[![Enterprise Grade](https://img.shields.io/badge/Enterprise%20Grade-Production%20Ready%20v2.5-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20800--218-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol%20v1.0-7C3AED?style=for-the-badge&logo=openai)](https://modelcontextprotocol.io)
[![NIST PQC Standards](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20FIPS%20204%20%7C%20FIPS%20205-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![AST + Gemini RAG](https://img.shields.io/badge/AST%20%2B%20Gemini%20RAG-In--Place%20%26%20Polyglot-FF6F00?style=for-the-badge&logo=google)](https://ai.google.dev)

---

## 📋 Visão Geral Executiva

O **NEXAVOR-QUANTUM-AUDIT (RustShield Quantum v2.0)** é uma plataforma unificada de **Engenharia de Segurança de Software de Nível Enterprise (AppSec, GRC & DevSecOps)**, desenvolvida para fornecer auditoria contínua, governança cibernética, mitigação de riscos na cadeia de suprimentos de software e transição de sistemas legados para criptografia pós-quântica resistente a algoritmos de Shor e Grover.

A plataforma integra análise estática sintática rigorosa (**Árvore Sintática Abstrata - AST**), inteligência artificial auditável guiada por RAG (**Google Gemini AI Engine**), servidor **MCP (Model Context Protocol)** para integração direta com IDEs (VSCode/Cursor), modelagem espectral de regressão via **Teoria das Ondas (Equações de Schrödinger / Solitons)** e orquestração de processos orientados a domínios (**DDD + SOA/BPMN**).

---

## 🎯 Principais Pilares do Sistema

### 1. Refatoração In-Place vs. Migração Polyglot (TargetMode)
A engine de AST e IA suporta duas vias operacionais no Studio de Refatoração:
- **OPÇÃO A: MIGRAÇÃO POLYGLOT (Target: Rust ou Go)**
  - Converte código legado (Python, Java, C++, TypeScript) para Rust (`Result<T, E>`, RAII) ou Go (`if err != nil`, Structs, Channels).
  - Saída obrigatória em extensões `.rs` ou `.go`.
- **OPÇÃO B: REFATORAÇÃO IN-PLACE (Target: Same-Language Hardening)**
  - Refatora, corrige vulnerabilidades (OWASP A03, NIST PQC) e moderniza o código **sem alterar a linguagem de origem** (ex: Python para Python Seguro, TypeScript para TypeScript Seguro, C++ para C++20 Seguro).
  - Preserva a extensão original do arquivo (`.py`, `.ts`, `.cpp`, `.java`).
  - Aplica padrões de segurança, verificação de tempo constante (`ConstantTimeEq`), substituição de primitivas quânticas vulneráveis e tratamento defensivo de erros nativo da linguagem original.

### 2. Servidor MCP (Model Context Protocol) — `@nexavor/mcp-server`
Exposição do endpoint `/api/mcp` com suporte ao padrão JSON-RPC 2.0 para integração com assistentes de IA e IDEs (Cursor/VSCode):
- **`analyze_ast`**: Análise sintática determinística e identificação de violações AST.
- **`refactor_code`**: Execução de refatoração In-Place ou Migração Polyglot enviando `{ code, language, target_mode: "IN_PLACE" | "RUST" | "GO" }`.
- **`calculate_fair`**: Cálculo matemático de métricas financeiras de risco (ALE, SLE, ARO, ROSI).

### 3. Sistema RAG (Retrieval-Augmented Generation) & Base Regulatória
Injeção automatizada de conhecimento regulatório e técnico no contexto do Gemini AI Engine:
- Ingestão das normas **NIST SP 800-218 (SSDF v1.1)**, **PCI-DSS v4.0 (Reqs 6.2/6.3)**, **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, **FIPS 205 (SLH-DSA)** e advisories em tempo real das bases **OSV.dev**, **RustSec** e **NVD**.

### 4. Arquitetura DDD (Domain-Driven Design) & Bounded Contexts
Estrutura modular e desacoplada em `src/domain/`:
- **`domain/astRefactorEngine.ts`**: Análise de AST e regras heurísticas determinísticas de correção.
- **`domain/grc.ts`**: Entidades e Value Objects do modelo FAIR para quantificação financeira de risco e avaliação de SLAs de segurança.
- **`domain/pqc.ts`**: Especificações de algoritmos FIPS 203/204/205 e verificação de tempo constante.
- **`domain/supplyChain.ts`**: Emissão de documentos SBOM em CycloneDX v1.5 com nível SLSA 3/4.
- **`domainEvents.ts`**: Disparo de eventos assíncronos (`CodeRefactoredEvent`, `VulnerabilityMitigatedEvent`).

### 5. SOA & BPMN (Orquestração de Workflows)
Modelo de orquestração assíncrona desacoplada (Temporal.io / Camunda 8):
`Audit -> Vulnerability Detection -> SLA Evaluation -> Decision Gateway (In-Place vs. Migration) -> AST/RAG Refactoring -> Tamper-Proof Ledger Signing -> GitHub PR / CI Gate Notification`.

### 6. Criptografia Pós-Quântica (NIST PQC) & Ledger Imutável
- Proteção contra algoritmos de Shor/Grover em chaves assimétricas clássicas (RSA, ECDSA, Ed25519).
- Suporte aos padrões **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** e **FIPS 205 (SLH-DSA)**.
- Trilha de auditoria em encadeamento criptográfico SHA-256 e sincronização Firestore com modo fallback de streaming.

---

## 🏛️ Arquitetura de Software e Fluxo de Dados

```
  +---------------------------------------------------------------------------------+
  |                       IDEs (Cursor / VSCode) / Agentes de IA                    |
  +---------------------------------------------------------------------------------+
                                           |
                              (JSON-RPC 2.0 / MCP Protocol)
                                           v
  +---------------------------------------------------------------------------------+
  | Servidor MCP (@nexavor/mcp-server)  --->  /api/mcp                              |
  |  - analyze_ast                                                                  |
  |  - refactor_code { target_mode: "IN_PLACE" | "RUST" | "GO" }                      |
  |  - calculate_fair { ALE, SLE, ARO, ROSI }                                       |
  +---------------------------------------------------------------------------------+
                                           |
                                           v
+---------------------------------------------------------------------------------------------------------------+
| Camada de Backend & API REST (Node.js + Express + TypeScript)                                                 |
|                                                                                                               |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | /api/audit/analyze       |  | /api/mcp                 |  | /api/badge/svg            |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | /api/audit/ast-refactor  |  | /api/github/refactor-pr  |  | /api/webhooks/github      |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|                 |                             |                             |                                 |
|                 v                             v                             v                                 |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | Bounded Contexts DDD     |  | Workflow BPMN            |  | Gemini AI Engine + RAG    |                   |
|   | (AST, GRC, PQC, SBOM)    |  | (Orquestração Temporal)  |  | (NIST / PCI-DSS Context)  |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
+---------------------------------------------------------------------------------------------------------------+
                                                        |
                                           (Server-Sent Events / REST)
                                                        v
+---------------------------------------------------------------------------------------------------------------+
| Frontend Enterprise (React 18 + Vite + Tailwind CSS + Framer Motion)                                          |
|                                                                                                               |
|  [ Dashboard GRC ] [ Refactor Studio (In-Place / Polyglot) ] [ PQC Hub ] [ CI/CD Multi-Cloud ]                |
|  [ Supply Chain SBOM ] [ Ledger Imutável SIEM ] [ Teoria das Ondas ] [ Workflow BPMN ]                        |
+---------------------------------------------------------------------------------------------------------------+
```

---

## 🚀 Como Executar Localmente

### Pré-requisitos
- **Node.js**: Versão 18 ou superior
- **npm**: Versão 9 ou superior
- **Git**

### Passo a Passo

1. **Clonar o Repositório**:
   ```bash
   git clone https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT.git
   cd NEXAVOR-QUANTUM-AUDIT
   ```

2. **Instalar as Dependências**:
   ```bash
   npm install
   ```

3. **Configurar as Variáveis de Ambiente**:
   ```bash
   cp .env.example .env
   ```
   *(Opcional: configure sua `GEMINI_API_KEY` para o motor de IA; a plataforma conta com fallback heurístico determinístico completo).*

4. **Executar em Modo de Desenvolvimento**:
   ```bash
   npm run dev
   ```

5. **Executar Testes e Lint**:
   ```bash
   npm run lint
   npm test
   ```

6. **Compilar para Produção**:
   ```bash
   npm run build
   npm start
   ```

7. **Acessar a Plataforma**:
   - **Interface Web**: `http://localhost:3000`
   - **Servidor MCP**: `http://localhost:3000/api/mcp`

---

## 🔌 Configuração do Servidor MCP no Cursor / VSCode

Para conectar o Cursor ou VSCode ao servidor MCP do NEXAVOR Quantum Audit:

1. Adicione a seguinte configuração no seu arquivo de MCP do Cursor (`~/.cursor/mcp.json`):
   ```json
   {
     "mcpServers": {
       "nexavor-quantum-audit": {
         "url": "http://localhost:3000/api/mcp",
         "transport": "http"
       }
     }
   }
   ```
2. As ferramentas `analyze_ast`, `refactor_code` e `calculate_fair` ficarão disponíveis para chamadas diretas pelo assistente.

---

## ⚙️ Configuração do GitHub Actions CI/CD Gate

O pipeline automatizado está configurado em `.github/workflows/ci.yml`:

```yaml
name: RustShield Quantum Security & CI Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  audit-and-build:
    name: Lint, Audit & Full-Stack Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - run: npm ci || npm install
      - run: npm run lint
      - run: npm run build
      - run: npm test
```

---

## 📑 Padrões Regulatórios e Formatos Suportados

- **NIST SP 800-218** (Secure Software Development Framework - SSDF v1.1)
- **ISO/IEC 27001:2022** (Controles Anexo A: A.8.8, A.8.28, A.8.30)
- **SOC 2 Type II** (Trust Services Criteria CC6.1, CC6.6, CC7.1, CC8.1)
- **PCI-DSS v4.0** (Software Security Framework)
- **NIST FIPS 203, FIPS 204, FIPS 205** (ML-KEM, ML-DSA e SLH-DSA)
- **OWASP CycloneDX v1.5 & ISO/IEC 5962 SPDX v2.3** (Padrões de SBOM)
- **OASIS SARIF v2.1.0** (Static Analysis Results Interchange Format)
- **MCP (Model Context Protocol)** (Especificação Anthropic / Model Context Protocol v1.0)

---

## 📄 Licença

Distribuído sob a licença **MIT**.

---

<p align="center">
  <sub>Desenvolvido com excelência técnica por <strong>NEXAVOR-QUANTUM-AUDIT / RustShield Quantum</strong>.</sub>
</p>

