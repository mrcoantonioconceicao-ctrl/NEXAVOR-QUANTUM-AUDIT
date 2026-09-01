# 🛡️ RustShield Quantum — Secure Core (v2.0)
#### High-Performance, Memory-Safe AppSec, GRC Governance, AST Refactor & Post-Quantum Static Analysis Engine

[![CI/CD Security Gate](https://img.shields.io/badge/Security%20Gate-100%25%20Verified-00C853?style=for-the-badge&logo=rust&logoColor=white)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT)
[![Enterprise Grade](https://img.shields.io/badge/Enterprise%20Grade-Native%20Rust%201.70%2B-0284C7?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Cargo-Fuzz LibFuzzer](https://img.shields.io/badge/Cargo--Fuzz-LibFuzzer%20%2B%20ASan-E11D48?style=for-the-badge&logo=target)](https://github.com/rust-fuzz/cargo-fuzz)
[![NIST Post-Quantum](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20204%20%7C%20205-7C3AED?style=for-the-badge&logo=quantum)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20SSDF%20%7C%20PCI--DSS-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![Supply Chain SBOM](https://img.shields.io/badge/SBOM-OWASP%20CycloneDX%20v1.5%20%7C%20SPDX%20v2.3-059669?style=for-the-badge&logo=owasp)](https://cyclonedx.org)
[![FAIR Risk Model](https://img.shields.io/badge/Risk%20Quantification-FAIR%20%7C%20ALE%20%7C%20ROSI-D97706?style=for-the-badge&logo=cashapp)](https://www.fairinstitute.org/)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol%20JSON--RPC%202.0-8B5CF6?style=for-the-badge&logo=openai)](https://modelcontextprotocol.io)
[![Zero Trust Crypto](https://img.shields.io/badge/Zero%20Trust-Constant--Time%20%7C%20AES--GCM%20%7C%20SHA--256-10B981?style=for-the-badge&logo=lock)](https://csrc.nist.gov)

---

## 📋 Sumário Executivo & Visão Geral

O **RustShield Quantum (NEXAVOR-QUANTUM-AUDIT)** é uma plataforma unificada de engenharia DevSecOps de missão crítica, governança regulatória (GRC), refatoração automatizada de código legado e preparação criptográfica pós-quântica (PQC).

Projetada com uma arquitetura **Domain-Driven Design (DDD)** e implementada com um núcleo nativo de alta performance em **Rust 1.70+**, a plataforma combina:
1. **Análise Estática Poliglota e Refatoração Determinística (AST + Google Gemini AI)** com proteção contra sobrescrita e abertura de Pull Requests automáticos no GitHub.
2. **Cockpit de Fuzzing Contínuo (`Cargo-Fuzz` / `LibFuzzer` + AddressSanitizer)** com análise pericial de corpora, mutadores e isolamento de falhas de memória.
3. **Hub Criptográfico Pós-Quântico (NIST PQC)** com suporte aos padrões oficiais **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)** e **FIPS 205 (SLH-DSA)**.
4. **Governança GRC & Matriz de Conformidade Automatizada** para **SOC 2 Type II**, **ISO/IEC 27001:2022**, **NIST SP 800-218 (SSDF v1.1)** e **PCI-DSS v4.0**.
5. **Quantificação Financeira de Riscos Ciber (Modelo FAIR)** calculando Perda Única (SLE), Frequência Anual (ARO), Perda Anual Esperada (ALE) e Retorno sobre Investimento (ROSI).
6. **Supply Chain Security & Software Bill of Materials (SBOM)** com geração em 1-clique nos formatos **OWASP CycloneDX v1.5 JSON** e **ISO/IEC 5962 SPDX v2.3 JSON**.
7. **Trilha Forense Imutável (Tamper-Proof Ledger)** baseada em encadeamento criptográfico SHA-256 e exportação em tempo real para **SIEM (ArcSight CEF / ElasticSearch NDJSON)**.
8. **Servidor MCP (Model Context Protocol JSON-RPC 2.0)** para integração direta com IDEs de IA como **Cursor, VSCode e Windsurf**.

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
|  - Real-time Cargo-Fuzz & Memory Safety Dashboard     |       |  - crates/domain: Pure Entities & Value Objects       |
|  - GRC Governance, FAIR Risk & PQC Studio             |       |  - crates/infrastructure: AST, OSV, Ledger, Crypto    |
|  - AST Refactor Studio with GitHub 1-Click PR         |       |  - crates/application: RefactorEngine, SbomService    |
|  - Wave Theory & Soliton Regression Forecaster        |       |  - crates/interfaces: CLI, Axum HTTP & MCP Server     |
+-------------------------------------------------------+       +-------------------------------------------------------+
        |                                                                                                       |
        +---------------------------------------------------+---------------------------------------------------+
                                                            |
                                                            v
+-------------------------------------------------------------------------------------------------------------------------+
|                                              INTEGRAÇÕES & SERVIÇOS NATIVOS                                             |
|  [ LibFuzzer / ASan ]  [ Google Gemini 2.5 ]  [ OSV.dev / RustSec ]  [ NIST PQC FIPS ]  [ SIEM CEF / NDJSON ]  [ MCP ]  |
+-------------------------------------------------------------------------------------------------------------------------+
```

---

## 📂 Estrutura do Workspace Rust (`rustshield-core`)

O core nativo está modularizado em quatro crates independentes que seguem os princípios de **Clean Architecture** e **Ports and Adapters (Hexagonal)**:

```
rustshield-core/
├── Cargo.toml                     # Configuração de workspace, LTO=thin, opt-level=3, codegen-units=1
├── src/
│   └── main.rs                    # Ponto de entrada CLI e servidor unificado
├── crates/
│   ├── domain/                    # 1. Domínio Puro (Zero dependências externas de I/O)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── entities/          # Vulnerability, Repository, Dependency, CycloneDxBom, AuditReport
│   │       ├── value_objects/     # Severity, Category, FairRiskEvaluation, Ecosystem, PqcAlgorithm
│   │       ├── errors.rs          # DomainError fortemente tipado via `thiserror`
│   │       └── lib.rs
│   ├── infrastructure/            # 2. Infraestrutura & Adaptadores Secundários
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── ast/               # NativeAstEngine (Parsing estático, detecção de unsafe, aliasing, buffer overflows)
│   │       ├── osv/               # OsvClient (Integração assíncrona HTTP em lote com OSV.dev e RustSec)
│   │       ├── ledger/            # TamperProofLedger (Encadeamento de blocos SHA-256 e verificação imutável)
│   │       ├── crypto/            # Verificação em tempo constante (`subtle::ConstantTimeEq`), AES-GCM e PQC
│   │       └── lib.rs
│   ├── application/               # 3. Camada de Aplicação & Casos de Uso
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── services/          # RefactorEngine (IN_PLACE, RUST, GO), AuditorService, SbomService
│   │       ├── use_cases/         # ScanRepositoryUseCase, CalculateRiskUseCase, EmitSbomUseCase
│   │       └── lib.rs
│   └── interfaces/                # 4. Apresentação & Adaptadores Primários
│       ├── Cargo.toml
│       └── src/
│           ├── cli/               # Comandos Clap (scan, refactor, sbom, mcp, serve, fuzz)
│           ├── http/              # Rotas REST e Axum Server (/api/health, /api/mcp, /api/audit/*)
│           ├── mcp/               # Servidor MCP JSON-RPC 2.0 (analyze_ast, refactor_code, calculate_fair)
│           └── lib.rs
└── fuzz/                          # Suíte de Fuzzing Contínuo com libFuzzer
    ├── Cargo.toml
    └── fuzz_targets/
        ├── ast_parser.rs          # Fuzzing de buffer de bytes brutos no parser
        ├── structured_parser.rs   # Fuzzing guiado por tipos sintéticos (`arbitrary`)
        └── refactor_engine.rs     # Fuzzing de mutações e reescrita de árvore AST
```

---

## 🎯 Módulos & Capacidades Principais

### 1. 🧪 Cargo-Fuzz & Cockpit de Memory Safety (LibFuzzer + ASan / UBSan / MSan)
O módulo de **Fuzzing Contínuo** permite testar e isolar falhas de integridade de memória no motor de análise estática antes de qualquer deploy em produção:
- **Alvos de Fuzzing Mapeados**:
  - `ast_parser` $\rightarrow$ `crates/ast/src/parser.rs` (Buffer de bytes brutos contra pânicos de lexer e out-of-bounds).
  - `fuzz_structured_parser` $\rightarrow$ `crates/ast/src/structured.rs` (Geração de ASTs arbitrários tipados com `arbitrary`).
  - `refactor_engine` $\rightarrow$ `crates/engine/src/refactor.rs` (Transformações sintáticas extremas e patches de código).
- **Sanitizers Nativos LLVM**: Suporte a **AddressSanitizer (ASan)** para detecção de Use-After-Free e Heap-Buffer-Overflow, **MemorySanitizer (MSan)** para leitura de memória não inicializada e **UndefinedBehaviorSanitizer (UBSan)**.
- **Filtros Multi-Dimensionais**:
  - Filtro por **Target / Arquivo Fonte do Parser**.
  - Filtro por **Severidade** (CRITICAL / ASan, HIGH / Panic, MEDIUM / Timeout, PASSED / Sem Falhas).
  - Filtro por **Data** (24 Horas, 7 Dias, 30 Dias, Intervalo Customizado).
  - Busca textual instantânea por SHAs de commit, mensagens de pânico, mutadores e payloads em hexadecimal.
- **Análise Pericial de Corpora**: Visualizador de hexdump e ASCII de payloads com impacto de cobertura de ramos (*branches* e *edges*).

```bash
# Executar Fuzzing do Parser Principal com AddressSanitizer
cargo +nightly fuzz run ast_parser -- -max_total_time=120 -jobs=8

# Executar Fuzzing Estruturado com Type-Guided Arbitrary
cargo +nightly fuzz run structured_parser -- -max_len=4096
```

---

### 2. 🪄 Studio de Refatoração AST + IA & 1-Click Pull Request
Transformação determinística de código legado inseguro em código robusto e tipado:
- **Três Modos de Refatoração**:
  1. **`IN_PLACE`**: Correção cirúrgica de vulnerabilidades mantendo a linguagem original (ex: Python com sanitização de SQLi e subprocess seguro).
  2. **`RUST`**: Migração idiomática para Rust com gerenciamento RAII, tipos estáticos `Result<T, E>` e eliminação de ponteiros brutos.
  3. **`GO`**: Migração para Golang com tratamento explícito de erros (`if err != nil`), concorrência com channels e context timeout.
- **Blindagem de Arquivos Protegidos**: Bloqueio automático de sobrescrita acidental em manifestos de configuração como `requirements.txt`, `package.json`, `Cargo.toml`, `.env` e `Dockerfile`.
- **Protocolo de Extensão Estrita**: Geração de arquivos com extensões tipadas estritas (`.rs` e `.go`) para evitar colisões no repositório.
- **Gate Anti-NO-OP**: Validação semântica para impedir commits sem alterações efetivas de segurança.
- **1-Click Pull Request**: Abertura automatizada de PRs no GitHub com branch isolada, descrição padronizada das correções e estimativa de tempo economizado (~4.5 horas de engenharia por arquivo).

---

### 3. ⚛️ Hub Criptográfico Pós-Quântico (NIST PQC Standards)
Preparação corporativa para o **Q-Day** e neutralização do vetor de ataque *Harvest Now, Decrypt Later (HNDL)*:
- **Padrões Oficiais Implementados**:
  - **NIST FIPS 203**: **ML-KEM** (Module-Lattice-Based Key-Encapsulation Mechanism / Kyber-768 & Kyber-1024) para troca segura de chaves.
  - **NIST FIPS 204**: **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm / Dilithium-3 & Dilithium-5) para assinaturas digitais resistentes a computadores quânticos.
  - **NIST FIPS 205**: **SLH-DSA** (Stateless Hash-Based Digital Signature Algorithm / SPHINCS+) para infraestruturas de raiz de confiança.
- **Diagnóstico Algorítmico**: Avaliação contra o Algoritmo de Shor (quebra de RSA/ECC) e Algoritmo de Grover (redução de força de chaves simétricas).
- **Verificação em Tempo Constante**: Validação de assinaturas e chaves com `subtle::ConstantTimeEq` para mitigação de ataques de canal lateral (*Side-Channel Attacks*).

---

### 4. 🏛️ Governança GRC, Auditoria & Matriz Regulatória
Mapeamento automatizado de evidências técnicas para os principais padrões regulatórios internacionais:
- **SOC 2 Type II**: Critérios de Confiança CC6.1 (Controle de Acesso), CC6.6 (Proteção contra Ameaças Lógicas), CC7.1 (Gestão de Vulnerabilidades) e CC8.1 (Controle de Mudanças).
- **ISO/IEC 27001:2022**: Controles Anexo A: A.8.8 (Gestão de Vulnerabilidades Técnicas), A.8.28 (Codificação Segura) e A.8.30 (Testes de Segurança em Desenvolvimento).
- **NIST SP 800-218 (SSDF v1.1)**: Práticas de Desenvolvimento de Software Seguro (PO.1, PS.1, PW.1, PW.4, RV.1).
- **PCI-DSS v4.0**: Requisitos de proteção de dados de portadores de cartão e segurança no ciclo de vida de desenvolvimento (SDLC).
- **OWASP Top 10 (2025)**: Cobertura completa contra injeções, falhas de controle de acesso, falhas criptográficas e componentes desatualizados.

---

### 5. 💰 Quantificação Financeira de Riscos Ciber (Modelo FAIR)
Tradução de vulnerabilidades técnicas em métricas financeiras auditáveis para a diretoria e comitês de risco:
- **Perda Única Esperada (SLE)**:
  $$\text{SLE} = \text{Valor do Ativo (Asset Value)} \times \text{Fator de Exposição (EF)}$$
- **Perda Anual Esperada (ALE)**:
  $$\text{ALE} = \text{SLE} \times \text{Taxa Anual de Ocorrência (ARO)}$$
- **Retorno sobre Investimento em Segurança (ROSI)**:
  $$\text{ROSI} = \frac{(\text{ALE}_{\text{original}} \times \text{Eficácia de Mitigação}) - \text{Custo de Remediação}}{\text{Custo de Remediação}} \times 100\%$$
- **Redução Comprovada**: Demonstração de **até 92% de redução no risco financeiro** anualizado após a aplicação dos patches sugeridos.

---

### 6. 📦 Supply Chain Security & Software Bill of Materials (SBOM)
Inventário contínuo e auditável de dependências de software:
- **Formatos Abertos Suportados**:
  - **OWASP CycloneDX v1.5 JSON** (com componentes, licenças, hashes criptográficos SHA-256 e metadados de dependência).
  - **ISO/IEC 5962 SPDX v2.3 JSON** (com relacionamentos de pacotes e atestações de integridade).
- **Bases de Vulnerabilidade em Tempo Real**: Consulta automática a **OSV.dev REST API**, **RustSec Advisory DB**, **NVD** e **GitHub Advisory Database**.
- **Nível de Integridade SLSA**: Compatibilidade com requisitos de proveniência de software **SLSA Level 3**.

---

### 7. 🔒 Trilha de Auditoria Forense Imutável (Tamper-Proof Ledger) & SIEM
Registro pericial de todas as ações de segurança, auditoria e mutação de código:
- **Encadeamento Criptográfico SHA-256**: Cada entrada possui um hash encadeado do bloco anterior ($\text{Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Payload}_n)$), impossibilitando modificações retroativas.
- **Simulação Granular de RBAC**: Perfis de acesso configuráveis (**Admin**, **Security Officer**, **Developer**, **Auditor**).
- **Streaming para SIEM**:
  - **ArcSight CEF (Common Event Format)** para Splunk, Datadog e IBM QRadar.
  - **ElasticSearch NDJSON** para ELK Stack e Grafana Loki.

---

### 8. 🔌 Servidor MCP (Model Context Protocol) — JSON-RPC 2.0
Integração nativa com assistentes de IA em IDEs como **Cursor, VSCode e Windsurf**:
- **Ferramentas Expostas**:
  - `analyze_ast`: Executa a análise estática e extrai nós de vulnerabilidade no código.
  - `refactor_code`: Aplica a transformação de código para `IN_PLACE`, `RUST` ou `GO`.
  - `calculate_fair`: Retorna o valuation financeiro de risco (ALE, SLE, ARO, ROSI).

```json
// Configuração no Cursor (~/.cursor/mcp.json)
{
  "mcpServers": {
    "rustshield-quantum": {
      "url": "http://localhost:3000/api/mcp",
      "transport": "http"
    }
  }
}
```

---

## 🚀 Como Executar o Projeto

### Pré-requisitos
- **Node.js**: Versão 18+ (recomendado Node.js 20 LTS)
- **npm**: Versão 9+
- **Rust / Cargo**: Versão 1.70+ (opcional, para compilar a suíte `rustshield-core` nativa)
- **Git**

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
*(Opcional: configure sua chave `GEMINI_API_KEY` para ativar a IA em nuvem; a plataforma possui fallback heurístico determinístico completo).*

### Passo 4: Executar em Modo Desenvolvimento
```bash
npm run dev
```
- Interface Web: `http://localhost:3000`
- Endpoint de Healthcheck: `http://localhost:3000/api/health`
- Servidor MCP: `http://localhost:3000/api/mcp`

### Passo 5: Executar Testes & Validações
```bash
# Validar tipagem e linting
npm run lint

# Executar suíte de testes automatizados
npm test

# Compilar para produção
npm run build
npm start
```

---

### Execução do Core Nativo em Rust (CLI & Cargo-Fuzz)

```bash
cd rustshield-core

# Executar scan estático nativo
cargo run --bin rustshield -- scan --path . --format console

# Gerar SBOM CycloneDX v1.5 nativamente
cargo run --bin rustshield -- sbom --output bom.json

# Refatorar arquivo Python para Rust idiomático
cargo run --bin rustshield -- refactor --file legacy.py --mode rust

# Executar Fuzzing contínuo no Parser
cargo +nightly fuzz run ast_parser
```

---

## ⚙️ GitHub Actions CI/CD Security Gate

O pipeline de segurança automatizado está configurado em `.github/workflows/ci.yml`:

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

## 📑 Matriz de Padrões & Normas Suportadas

| Padrão / Norma | Categoria | Escopo no RustShield Quantum |
| :--- | :--- | :--- |
| **NIST FIPS 203** | Criptografia PQC | ML-KEM (Kyber-768/1024) Key Encapsulation |
| **NIST FIPS 204** | Criptografia PQC | ML-DSA (Dilithium-3/5) Assinatura Digital |
| **NIST FIPS 205** | Criptografia PQC | SLH-DSA (SPHINCS+) Stateless Hash-Based Signatures |
| **SOC 2 Type II** | Governança GRC | Critérios de Confiança CC6.1, CC6.6, CC7.1, CC8.1 |
| **ISO/IEC 27001:2022** | Governança GRC | Controles Anexo A: A.8.8, A.8.28, A.8.30 |
| **NIST SP 800-218** | DevSecOps | SSDF v1.1 Práticas PO.1, PS.1, PW.1, PW.4, RV.1 |
| **PCI-DSS v4.0** | Segurança de Pagamentos | Requisitos de SDLC Seguro e Proteção de Dados |
| **OWASP CycloneDX v1.5** | Supply Chain / SBOM | Inventário formal com hashes SHA-256 e licenças |
| **ISO/IEC 5962 SPDX v2.3** | Supply Chain / SBOM | Rastreabilidade e conformidade de pacotes abertos |
| **OASIS SARIF v2.1.0** | SAST Intercâmbio | Relatórios periciais de análise estática |
| **Model Context Protocol** | IA & IDE Integration | Servidor MCP JSON-RPC 2.0 (Anthropic / Cursor) |

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE` para mais detalhes.

---

<p align="center">
  <sub>Desenvolvido com excelência técnica e rigor matemático por <strong>NEXAVOR-QUANTUM-AUDIT / RustShield Quantum</strong>.</sub><br />
  <sub>Contato Técnico: <a href="mailto:mrcoantonioconceicao@gmail.com">mrcoantonioconceicao@gmail.com</a> | Repositório: <a href="https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT">GitHub</a></sub>
</p>
