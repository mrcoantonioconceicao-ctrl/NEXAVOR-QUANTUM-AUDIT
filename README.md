# 🛡️ RustShield Secure Core (v2.0)
#### High-Performance, Memory-Safe AppSec, GRC Governance & Static Analysis Engine

[![CI/CD Security Gate](https://img.shields.io/badge/Security%20Gate-100%25%20Verified-00C853?style=for-the-badge&logo=rust&logoColor=white)](https://github.com/)
[![Enterprise Grade](https://img.shields.io/badge/Enterprise%20Grade-Native%20Rust%201.70%2B-0284C7?style=for-the-badge&logo=rust)](https://www.rust-lang.org)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20SSDF-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![MCP Protocol](https://img.shields.io/badge/MCP-Model%20Context%20Protocol%20JSON--RPC%202.0-7C3AED?style=for-the-badge&logo=openai)](https://modelcontextprotocol.io)
[![Zero Trust Crypto](https://img.shields.io/badge/Zero%20Trust-Constant--Time%20%7C%20AES--GCM%20%7C%20Ed25519-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov)

---

## 📋 Visão Geral Executiva

O **RustShield Secure Core** é um ecossistema de alta performance escrito inteiramente em **Rust nativo (v1.70+)**, projetado para auditoria determinística de segurança de software, governança GRC quantificada (modelo FAIR), geração de SBOMs padronizados (OWASP CycloneDX v1.5) e integração via **Model Context Protocol (MCP)** para IDEs como Cursor e VSCode.

A arquitetura do backend segue rigorosamente os padrões de **Domain-Driven Design (DDD)**, **Zero Trust** e **Garantia de Segurança de Memória (Kernel-Level)**, com verificação de tempo constante (`subtle::ConstantTimeEq`), parsing estático AST resiliente a pânicos e trilha de auditoria imutável encadeada via SHA-256.

---

## 🏛️ Estrutura do Workspace Rust (`rustshield-core`)

O core nativo está modularizado em quatro crates independentes e coesas:

```
rustshield-core/
├── Cargo.toml                     # Workspace configuration & profile optimizations (LTO, opt-level 3)
├── src/
│   └── main.rs                    # Entrypoint CLI & Servidor HTTP/MCP
├── crates/
│   ├── domain/                    # 1. Domínio Puro (Zero dependências I/O ou Frameworks)
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── entities/          # Vulnerability, Repository, Dependency, CycloneDxBom, AuditReport
│   │       ├── value_objects/     # Severity, Category, FairRiskEvaluation, Ecosystem
│   │       ├── errors.rs          # DomainError fortemente tipado com thiserror
│   │       └── lib.rs
│   ├── infrastructure/            # 2. Infraestrutura & Adaptadores Secundários
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── ast/               # NativeAstEngine (Análise estática de vulnerabilidades e injeções)
│   │       ├── osv/               # OsvClient (Integração assíncrona HTTP em lote com OSV.dev)
│   │       ├── ledger/            # TamperProofLedger (Encadeamento de hashes SHA-256 e Constant-Time)
│   │       ├── crypto/            # Verificação e hashing com subtle::ConstantTimeEq
│   │       └── lib.rs
│   ├── application/               # 3. Camada de Aplicação & Casos de Uso
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── services/          # RefactorEngine (IN_PLACE, RUST, GO), AuditorService, SbomService
│   │       ├── use_cases/         # ScanRepositoryUseCase, CalculateRiskUseCase
│   │       └── lib.rs
│   └── interfaces/                # 4. Camada de Apresentação & Adaptadores Primários
│       ├── Cargo.toml
│       └── src/
│           ├── cli/               # Comandos Clap (scan, refactor, sbom, mcp, serve)
│           ├── http/              # Rotas REST e Axum Server (/api/health, /api/mcp, /api/audit/*)
│           ├── mcp/               # Servidor MCP JSON-RPC 2.0 (analyze_ast, refactor_code, calculate_fair)
│           └── lib.rs
└── fuzz/                          # Suíte de Fuzzing Contínuo (libFuzzer para o NativeAstEngine)
    ├── Cargo.toml
    └── fuzz_targets/
        └── ast_parser.rs
```

---

## 🎯 Capacidades Principais

### 1. Refatoração Determinística de Código (`RefactorEngine`)
- **IN_PLACE**: Hardening e mitigação de vulnerabilidades (injeções, ponteiros inseguros, deserialização RCE) mantendo a linguagem original.
- **RUST**: Migração idiomática para Rust com checagem de tipos estática, `Result<T, E>` e RAII.
- **GO**: Migração para Go estruturado com checagem de erro explícita (`if err != nil`).

### 2. Servidor MCP (Model Context Protocol) — JSON-RPC 2.0
Ferramentas expostas nativamente para IDEs (Cursor / VSCode / Windsurf):
- **`analyze_ast`**: Análise sintática determinística e identificação de violações de segurança.
- **`refactor_code`**: Execução de hardening de código legado (`IN_PLACE`, `RUST`, `GO`).
- **`calculate_fair`**: Cálculo de risco financeiro cibernético (ALE, SLE, ARO, ROSI).

### 3. Modelo FAIR & Governança GRC
- Cálculo de **Perda Única Esperada (SLE)**: $\text{SLE} = \text{Asset Value} \times \text{Exposure Factor}$.
- Cálculo de **Perda Anual Esperada (ALE)**: $\text{ALE} = \text{SLE} \times \text{ARO}$.
- Cálculo de **Retorno sobre Investimento em Segurança (ROSI)**: $\text{ROSI} = \frac{(\text{ALE} \times \text{Mitigation}) - \text{Cost}}{\text{Cost}} \times 100\%$.

### 4. Software Bill of Materials (SBOM CycloneDX v1.5)
- Emissão de inventário formal de dependências em formato JSON compatível com OWASP CycloneDX v1.5 e verificação contínua de integridade de hashes.

---

## 🚀 Como Executar o Core em Rust

### CLI RustShield:
```bash
# Compilar e executar a varredura em um diretório
cargo run --bin rustshield -- scan --path . --format console

# Gerar SBOM CycloneDX v1.5
cargo run --bin rustshield -- sbom --output bom.json

# Refatorar código legado para Rust idiomático
cargo run --bin rustshield -- refactor --file legacy.py --mode rust

# Iniciar o Servidor API e MCP
cargo run --bin rustshield -- serve --port 3000
```

### Fuzzing do Parser AST:
```bash
cd rustshield-core
cargo +nightly fuzz run ast_parser
```
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

