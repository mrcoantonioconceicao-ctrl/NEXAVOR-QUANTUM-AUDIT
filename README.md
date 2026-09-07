# 🛡️ RustShield Quantum — Secure Core (v2.2)
#### High-Performance, Memory-Safe AppSec, GRC Governance, AST Refactor, GraphRAG, Axum IPC Daemon & Post-Quantum Static Analysis Engine

[![CI/CD Security Gate](https://img.shields.io/badge/Security%20Gate-100%25%20Verified-00C853?style=for-the-badge&logo=rust&logoColor=white)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT)
[![Enterprise Grade](https://img.shields.io/badge/Enterprise%20Grade-Native%20Rust%201.70%2B-0284C7?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Axum Daemon](https://img.shields.io/badge/Rust%20Daemon-Axum%20127.0.0.1%3A4040-FE4A49?style=for-the-badge&logo=rust)](https://github.com/tokio-rs/axum)
[![GraphRAG Neo4j](https://img.shields.io/badge/GraphRAG-Neo4j%20Cypher%20%2B%20Vector-0284C7?style=for-the-badge&logo=neo4j&logoColor=white)](https://neo4j.com)
[![Cargo-Fuzz LibFuzzer](https://img.shields.io/badge/Cargo--Fuzz-LibFuzzer%20%2B%20ASan-E11D48?style=for-the-badge&logo=target)](https://github.com/rust-fuzz/cargo-fuzz)
[![NIST Post-Quantum](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20204%20%7C%20205-7C3AED?style=for-the-badge&logo=quantum)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20SSDF%20%7C%20PCI--DSS-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![Supply Chain SBOM](https://img.shields.io/badge/SBOM-OWASP%20CycloneDX%20v1.5%20%7C%20SPDX%20v2.3-059669?style=for-the-badge&logo=owasp)](https://cyclonedx.org)
[![FAIR Risk Model](https://img.shields.io/badge/Risk%20Quantification-FAIR%20%7C%20ALE%20%7C%20ROSI-D97706?style=for-the-badge&logo=cashapp)](https://www.fairinstitute.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol%20SSE%20%2B%20JSON--RPC%202.0-8B5CF6?style=for-the-badge&logo=openai)](https://modelcontextprotocol.io)

---

## 📋 Sumário Executivo & Visão Geral (v2.2)

O **RustShield Quantum (NEXAVOR-QUANTUM-AUDIT)** é uma plataforma unificada de engenharia DevSecOps de missão crítica, governança regulatória (GRC), refatoração automatizada de código legado, análise relacional em grafo (GraphRAG) e preparação criptográfica pós-quântica (PQC).

Projetada com uma arquitetura **Domain-Driven Design (DDD)** e implementada com um núcleo nativo de alta performance em **Rust 1.70+**, a versão v2.2 incorpora:

1. **Daemon IPC de Alta Performance em Rust Axum (`127.0.0.1:4040`)**: Servidor interno Axum/Tokio expondo endpoints de alta velocidade (`/api/ast/parse`, `/api/fuzz/verify`, `/api/crypto/constant-time`) integrados ao cliente TypeScript Gateway (`/server/rustDaemonClient.ts`) com controle de timeout de **3000ms** via `AbortController`.
2. **Servidor MCP Completo (SSE / JSON-RPC 2.0)**: Protocolo Model Context Protocol em `/api/mcp` suportando conexões Server-Sent Events (SSE) e requisições JSON-RPC 2.0 com ferramentas como `analyze_ast`, `refactor_code`, `calculate_fair`, `query_impact_graph`, `scan_sbom` e `generate_constant_time_harness`.
3. **Mecanismo de Draft PR Seguro (Human-in-the-Loop)**: Criação de Pull Requests no GitHub em modo **Draft** (`draft: true`) acompanhadas de relatórios formais de sanitização Cargo-Fuzz (AddressSanitizer / LSan) e lista de checagem obrigatória para aprovação humana.
4. **Resiliência no HybridRAG com Circuit Breaker (Timeout de 1500ms)**: Proteção em `src/services/hybridRagService.ts` contra latência no Neo4j, alternando suavemente para busca vetorial pura (`Qdrant`/`pgvector`) e informando a flag `graphContextAvailable: false` ao motor Gemini AI.
5. **Análise Estática Poliglota e Refatoração Determinística (AST + Gemini AI)** com motor de envio atômico em lote via **GitHub Git Data API (`/server/githubGitService.ts`)** usando `@octokit/rest`.
6. **CodeReviewWorkbench & Isolamento Pericial de Riscos**: Painel interativo para isolamento de falhas de alta severidade em **Memory Safety** e **Post-Quantum Cryptography (PQC)**.
7. **Visualizador Interativo GraphRAG com Framer Motion & Snapshots**: Animações *spring*, auras luminosas para vulnerabilidades e salvamento de estado de zoom/filtros no `localStorage` com exportação/importação JSON em 1-clique.
8. **Hub Criptográfico Pós-Quântico (NIST PQC)** com suporte aos padrões oficiais **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** e **FIPS 205 (SLH-DSA)**.
9. **Governança GRC & Quantificação FAIR**: Matriz de evidências para **SOC 2**, **ISO 27001**, **NIST SSDF** e **PCI-DSS**, além de valuation financeiro (SLE, ALE, ROSI).
10. **Supply Chain Security & Trilha Forense SHA-256**: Exportação SBOM (**OWASP CycloneDX v1.5** / **SPDX v2.3**) e streaming para SIEM (**ArcSight CEF** / **ElasticSearch NDJSON**).

---

## 🏛️ Arquitetura Geral do Ecossistema

```
+-------------------------------------------------------------------------------------------------------------------------+
|                                    RUSTSHIELD QUANTUM ENTERPRISE ARCHITECTURE                                           |
+-------------------------------------------------------------------------------------------------------------------------+
                                                            |
        +---------------------------------------------------+---------------------------------------------------+
        |                                                                                                       |
        v                                                                                                       v
+-------------------------------------------------------+       +-------------------------------------------------------+
|              FRONTEND WEB & COCKPIT UI                |       |             RUSTSHIELD SECURE CORE (RUST)             |
|  - React 18 + TypeScript + Tailwind CSS               |       |  - 100% Native Safe Rust 1.70+ Workspace              |
|  - GraphRAG Visualizer + Snapshots + Framer Motion    |       |  - crates/domain: Pure Entities & Value Objects       |
|  - Hybrid RAG Service (Vector + Neo4j Graph)          |       |  - crates/infrastructure: AST, OSV, Ledger, Crypto    |
|  - Real-time Cargo-Fuzz & Memory Safety Dashboard     |       |  - crates/application: RefactorEngine, SbomService    |
|  - GRC Governance, FAIR Risk & PQC Studio             |       |  - crates/interfaces: CLI, Axum HTTP & MCP Server     |
|  - AST Refactor Studio with GitHub 1-Click PR         |       |                                                       |
+-------------------------------------------------------+       +-------------------------------------------------------+
        |                                                                                                       |
        +---------------------------------------------------+---------------------------------------------------+
                                                            |
                                                            v
+-------------------------------------------------------------------------------------------------------------------------+
|                                              INTEGRAÇÕES & SERVIÇOS NATIVOS                                             |
|  [ Neo4j Cypher / GraphRAG ]  [ Hybrid Vector RAG ]  [ Google Gemini 2.5 ]  [ LibFuzzer / ASan ]  [ NIST PQC ]  [ MCP ]  |
+-------------------------------------------------------------------------------------------------------------------------+
```

---

## 📂 Estrutura do Workspace Rust (`rustshield-core`) & Frontend TypeScript

O ecossistema é organizado em camadas limpas de **Clean Architecture** e **Domain-Driven Design (DDD)**:

```
├── src/                                   # Frontend & Módulos de Domínio TypeScript
│   ├── domain/                            # Entidades, Value Objects e Motores Sintáticos
│   │   ├── knowledgeGraph/                # Ontologia do Grafo e Serviços
│   │   │   ├── schema.ts                  # Esquema Neo4j Cypher, Constraints e Indexes
│   │   │   ├── GraphSyncService.ts        # Sincronização e Mapeamento de Entidades
│   │   │   └── types.ts                   # Interfaces fortemente tipadas do Grafo
│   │   ├── rag/                           # RAG Híbrido e Recuperação Relacional
│   │   │   └── HybridRAGService.ts        # Busca Paralela (Vetores + Cypher), Reranking e Telemetria
│   │   ├── astRefactorEngine.ts           # Motor de Análise Sintática e Refatoração AST
│   │   ├── polyglotStaticEngine.ts        # Análise Estática Poliglota (Rust, Go, TS, Python, Solidity)
│   │   └── types.ts                       # Modelos Unificados de Auditoria DevSecOps
│   ├── components/                        # Componentes UI Reutilizáveis & Cockpits
│   │   ├── GraphRagVisualizer.tsx         # Visualizador de Grafo em Tempo Real (Framer Motion + Snapshots)
│   │   ├── AstRefactorStudio.tsx          # Studio de Refatoração Sintática AST
│   │   ├── ComplianceGovernanceHub.tsx    # Matriz GRC, SSDF, PCI-DSS e ISO 27001
│   │   └── ...
│   └── services/                          # Serviços de Exportação (SBOM, PDF, SIEM)
│
└── rustshield-core/                       # Core Nativo em Safe Rust (1.70+)
    ├── Cargo.toml                         # Workspace, LTO=thin, opt-level=3
    ├── crates/
    │   ├── domain/                        # Pure Domain Entities
    │   ├── infrastructure/                # AST, OSV, Ledger SHA-256, Constant-Time Crypto
    │   ├── application/                   # RefactorEngine, AuditorService, SbomService
    │   └── interfaces/                    # Axum HTTP, Clap CLI, Servidor MCP JSON-RPC
    └── fuzz/                              # Targets LibFuzzer + AddressSanitizer
```

---

## 🎯 Módulos & Capacidades Principais

### 1. 🕸️ Knowledge Graph Ontology & GraphRAG Neo4j (`schema.ts` + `HybridRAGService.ts`)
O módulo de **Grafo de Conhecimento** fornece uma representação estruturada de todo o repositório auditado:
- **Ontologia de Nós**:
  - `:CodeFile`: Arquivos de código-fonte (`.rs`, `.sol`, `.ts`, `.py`, `.go`).
  - `:ASTFunction`: Funções extraídas da árvore sintática.
  - `:CryptoAlgorithm`: Primitivas criptográficas em uso (pós-quânticas e clássicas).
  - `:Vulnerability`: Falhas e cve/cwe detectados com severidade.
  - `:ComplianceRule`: Requisitos regulatórios (SOC2, ISO 27001, PCI-DSS, NIST SSDF).
  - `:SBOMPackage`: Pacotes e dependências registradas.
- **Relacionamentos Cypher**: `:CALLS`, `:USES_CRYPTO`, `:VIOLATES`, `:DEPENDS_ON`, `:HAS_VULNERABILITY`, `:AFFECTS_MODULE`, `:COMPLIES_WITH`.
- **RAG Híbrido (Vetorial + Grafo)**: Execução em paralelo de buscas semânticas em vetor e travessias em subgrafos relacionais Cypher com reranking e telemetria de latência (`totalMs`, `vectorRetrievalMs`, `graphRetrievalMs`).

---

### 2. 📸 GraphRAG Visualizer Interativo & Snapshots de Análise (`GraphRagVisualizer.tsx`)
Cockpit visual avançado para exploração do subgrafo de dependências e risco:
- **Animações Framer Motion**:
  - Transições suaves *spring* na entrada de nós.
  - Pulso luminoso (*glowing aura*) diferenciado em **Vulnerability** (tom rose) e **ComplianceRule** (tom emerald).
- **Controle de Zoom Dinâmico**: Ajuste da escala visual entre `60%` e `160%` com reset instantâneo para `100%`.
- **Sistema de Snapshots da Análise**:
  - Salva o estado exato da auditoria (zoom, filtros ativos por rótulo/severidade, termo de busca, nó selecionado e abas).
  - Persistência automática no `localStorage`.
  - Restauração do estado da análise em 1-clique.
  - Exportação e importação de snapshots em formato **JSON**.

---

### 3. 🧪 Cargo-Fuzz & Cockpit de Memory Safety (LibFuzzer + ASan / UBSan / MSan)
O módulo de **Fuzzing Contínuo** isola falhas de integridade de memória no motor sintático:
- **Sanitizers Nativos LLVM**: AddressSanitizer (ASan), MemorySanitizer (MSan) e UndefinedBehaviorSanitizer (UBSan).
- **Alvos de Fuzzing**: `ast_parser`, `structured_parser` e `refactor_engine`.
- **Análise Pericial**: Inspeção de hexdump/ASCII e rastreamento de cobertura de ramos.

```bash
# Executar Fuzzing do Parser Principal com AddressSanitizer
cargo +nightly fuzz run ast_parser -- -max_total_time=120 -jobs=8
```

---

### 4. 🪄 Studio de Refatoração AST + IA & Envio Atômico em Lote (Git Data API)
Transformação determinística de código legado em código seguro e integração contínua com o GitHub:
- **Modos de Refatoração**: `IN_PLACE`, `RUST` e `GO`.
- **Proteção de Arquivos**: Bloqueio contra sobrescrita acidental em manifestos (`Cargo.toml`, `package.json`, `.env`, `Dockerfile`).
- **Motor de Envio Atômico em Lote (`githubGitService.ts`)**: Utiliza a **GitHub Git Data API** (`Blobs` -> `Tree` -> `Commit` -> `UpdateRef`) com `@octokit/rest` para enviar simultaneamente múltiplos arquivos refatorados (ex: `ast_parser.rs`, `Cargo.toml`, `package.json`, `audit_log.rs`, `lib.rs`) em um único commit atômico.
- **Padronização de Mensagens de Commit**:
  - Remediações de segurança: `fix(security): remediação automática de dependências e memory safety via RustShield`
  - Refatorações sintáticas: `refactor(ast-ai): remediação completa e refatoração de código legado [RustShield Quantum]`
- **1-Click Pull Request**: Abertura automatizada de PRs no GitHub com branch isolada (`rustshield-patch-*` ou `rustshield-legacy-refactor-*`).

---

### 5. 🔍 CodeReviewWorkbench & Isolamento Pericial de Riscos
Painel interativo para revisão e homologação técnica de vulnerabilidades:
- **Filtragem por Perfil de Risco**: Botões rápidos para isolar falhas de alta severidade (CVSS >= 7.0 / Critical / High).
- **Filtro de Memory Safety**: Isola falhas de integridade de memória, corrupção de buffer, vazamento e uso de `unsafe`.
- **Filtro de Post-Quantum Cryptography (PQC)**: Destaca vulnerabilidades em algoritmos clássicos suscetíveis ao Q-Day (RSA/ECC) e impulsiona a migração para FIPS 203/204/205.

---

### 5. ⚛️ Hub Criptográfico Pós-Quântico (NIST PQC Standards)
Preparação corporativa contra o **Q-Day**:
- **Padrões NIST**: **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** e **FIPS 205 (SLH-DSA)**.
- **Constant-Time Verification**: Proteção contra ataques de canal lateral via `subtle::ConstantTimeEq`.

---

### 6. 🏛️ Governança GRC, Auditoria & Matriz Regulatória
Matriz de evidências para **SOC 2 Type II**, **ISO/IEC 27001:2022**, **NIST SP 800-218 (SSDF v1.1)** e **PCI-DSS v4.0**.

---

### 7. 💰 Quantificação Financeira de Riscos Ciber (Modelo FAIR)
Valuation financeiro calculando **SLE**, **ALE** e **ROSI** com demonstração de redução de risco financeiro anualizado.

---

### 8. 📦 Supply Chain Security & Software Bill of Materials (SBOM)
Inventário de software em **OWASP CycloneDX v1.5 JSON** e **ISO/IEC 5962 SPDX v2.3 JSON** integrado a bases em tempo real (**OSV.dev**, **RustSec**).

---

### 9. 🔒 Trilha de Auditoria Forense Imutável (Tamper-Proof Ledger) & SIEM
Encadeamento criptográfico SHA-256 com streaming para SIEM em **ArcSight CEF** e **ElasticSearch NDJSON**.

---

### 10. 🔌 Servidor MCP (Model Context Protocol) — JSON-RPC 2.0
Integração nativa com assistentes de IA em IDEs como **Cursor, VSCode e Windsurf** através das ferramentas `analyze_ast`, `refactor_code` e `calculate_fair`.

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
- **Node.js**: Versão 18+ (recomendado Node.js 20 LTS)
- **npm**: Versão 9+
- **Rust / Cargo**: Versão 1.70+ (opcional, para compilar o core nativo `rustshield-core`)

---

### Passo 1: Clonar o Repositório
```bash
git clone https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT.git
cd NEXAVOR-QUANTUM-AUDIT
```

### Passo 2: Instalar Dependências
```bash
npm install
```

### Passo 3: Configurar Variáveis de Ambiente
```bash
cp .env.example .env
```

### Passo 4: Executar em Modo Desenvolvimento
```bash
npm run dev
```
- Interface Web: `http://localhost:3000`
- Endpoint de Healthcheck: `http://localhost:3000/api/health`
- Servidor MCP: `http://localhost:3000/api/mcp`

### Passo 5: Executar Testes & Validações
```bash
# Validar tipagem estrita com TypeScript compiler
npm run lint

# Executar suíte de testes automatizados
npm test

# Compilar para produção
npm run build
npm start
```

---

## 📑 Matriz de Padrões & Normas Suportadas

| Padrão / Norma | Categoria | Escopo no RustShield Quantum |
| :--- | :--- | :--- |
| **Neo4j Cypher / GraphRAG** | Grafo de Conhecimento | Ontologia `:CodeFile`, `:Vulnerability`, `:ComplianceRule`, `:ASTFunction` |
| **NIST FIPS 203** | Criptografia PQC | ML-KEM (Kyber-768/1024) Key Encapsulation |
| **NIST FIPS 204** | Criptografia PQC | ML-DSA (Dilithium-3/5) Assinatura Digital |
| **NIST FIPS 205** | Criptografia PQC | SLH-DSA (SPHINCS+) Stateless Hash-Based Signatures |
| **SOC 2 Type II** | Governança GRC | Critérios de Confiança CC6.1, CC6.6, CC7.1, CC8.1 |
| **ISO/IEC 27001:2022** | Governança GRC | Controles Anexo A: A.8.8, A.8.28, A.8.30 |
| **NIST SP 800-218** | DevSecOps | SSDF v1.1 Práticas PO.1, PS.1, PW.1, PW.4, RV.1 |
| **PCI-DSS v4.0** | Segurança de Pagamentos | Requisitos de SDLC Seguro e Proteção de Dados |
| **OWASP CycloneDX v1.5** | Supply Chain / SBOM | Inventário formal com hashes SHA-256 e licenças |
| **ISO/IEC 5962 SPDX v2.3** | Supply Chain / SBOM | Rastreabilidade e conformidade de pacotes abertos |
| **Model Context Protocol** | IA & IDE Integration | Servidor MCP JSON-RPC 2.0 (Anthropic / Cursor) |

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para mais detalhes.

---

<p align="center">
  <sub>Desenvolvido com excelência técnica, rigor matemático e arquitetura DDD por <strong>NEXAVOR-QUANTUM-AUDIT / RustShield Quantum</strong>.</sub><br />
  <sub>Contato Técnico: <a href="mailto:mrcoantonioconceicao@gmail.com">mrcoantonioconceicao@gmail.com</a> | Repositório: <a href="https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT">GitHub</a></sub>
</p>
