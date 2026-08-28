# 🛡️ NEXAVOR-QUANTUM-AUDIT (RustShield Quantum)
### Enterprise DevSecOps, GRC Governance, Software Supply Chain & Post-Quantum Cryptography (NIST PQC) Suite

[![CI/CD Security Gate](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT/actions/workflows/ci.yml/badge.svg)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT/actions)
[![Enterprise Grade](https://img.shields.io/badge/Enterprise%20Grade-Production%20Ready%20v2.5-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20800--218-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![SBOM Standards](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5%20%7C%20SPDX%20v2.3-9C27B0?style=for-the-badge&logo=json)](https://cyclonedx.org)
[![NIST PQC Standards](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20FIPS%20204%20%7C%20FIPS%20205-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![AST + Gemini AI](https://img.shields.io/badge/AST%20%2B%20Gemini%20AI-Deterministic%20Refactor-FF6F00?style=for-the-badge&logo=google)](https://ai.google.dev)
[![Multi-Cloud CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20%7C%20GitLab%20%7C%20Azure%20%7C%20Bitbucket-3178C6?style=for-the-badge&logo=githubactions)](https://github.com/mrcoantonioconceicao-ctrl/NEXAVOR-QUANTUM-AUDIT)

---

## 📋 Visão Geral Executiva

O **NEXAVOR-QUANTUM-AUDIT (RustShield Quantum)** é uma plataforma unificada de **Engenharia de Segurança de Software de Nível Enterprise (AppSec, GRC & DevSecOps)**, desenvolvida para fornecer auditoria contínua, governança cibernética, mitigação de riscos na cadeia de suprimentos de software e transição de sistemas legados para criptografia pós-quântica resistente a algoritmos de Shor e Grover.

A plataforma integra análise estática sintática rigorosa (**Árvore Sintática Abstrata - AST**), inteligência artificial auditável (**Google Gemini**), modelagem espectral de regressão via **Teoria das Ondas (Equações de Schrödinger / Solitons)** e conformidade contínua com os principais marcos regulatórios globais.

---

## 🎯 Principais Pilares do Sistema

1. **Governança, Risco & Conformidade (GRC Hub)**:
   - Matriz automatizada de conformidade para **SOC 2 Type II**, **ISO/IEC 27001:2022**, **NIST SP 800-218 (SSDF v1.1)**, **PCI-DSS v4.0** e **OWASP Top 10 (2025/2021)**.
   - Gestão de SLAs de remediação rigorosos: Crítico (24h), Alto (7d), Médio (30d).

2. **Quantificação Financeira FAIR & ROSI**:
   - Cálculo matemático da Perda Anual Esperada (**ALE**), Perda Única (**SLE**), Frequência Anual de Ocorrência (**ARO**) e Retorno sobre Investimento em Segurança (**ROSI**), demonstrando até **92% de redução no risco financeiro**.

3. **Software Bill of Materials (SBOM) & Supply Chain Security**:
   - Emissão de inventários em **OWASP CycloneDX v1.5 JSON** e **ISO/IEC 5962 SPDX v2.3 JSON** com rastreabilidade SLSA Level 3 e hashes criptográficos SHA-256.
   - Consulta síncrona aos bancos globais **OSV.dev**, **RustSec Advisory Database**, **NIST NVD** e **GitHub Security Advisory Database**.

4. **Refatoração Determinística e Automação de Pull Requests (AST + Google Gemini)**:
   - Correção automatizada de código inseguro com geração de branches isoladas e abertura automática de **Pull Requests no GitHub via API REST** (com commit físico sanitizado em Base64 e auto-recuperação de SHA).
   - Suporte poliglota: Rust, TypeScript, Node.js, Python, Go, C/C++, Solidity/Web3.

5. **Hub Criptográfico Pós-Quântico (NIST PQC Hub)**:
   - Detecção de vulnerabilidades aos algoritmos quânticos de Shor e Grover em chaves assimétricas clássicas (RSA, ECDSA, DH, Ed25519).
   - Verificação de tempo constante (`ConstantTimeEq`) para mitigação de ataques de canal lateral (*Timing Attacks*).
   - Transição e conformidade com os novos padrões oficiais do NIST:
     - **FIPS 203 — ML-KEM (Kyber-768 / Kyber-1024)** (Encapsulamento de Chaves)
     - **FIPS 204 — ML-DSA (Dilithium-65 / Dilithium-87)** (Assinatura Digital)
     - **FIPS 205 — SLH-DSA (SPHINCS+)** (Assinatura Stateless)
     - **FN-DSA (Falcon)** (Assinatura Compacta)

6. **Trilha de Auditoria Imutável (Ledger Forense) & Integração SIEM**:
   - Encadeamento de blocos criptográficos SHA-256 (*Hash Chain Tamper-Proof*) garantindo integridade de ponta a ponta.
   - Streaming nativo nos formatos **CEF (Splunk, Datadog, ArcSight, QRadar)** e **JSON-ND (ElasticSearch/Logstash)**.

7. **Pipeline Studio Multi-Cloud & CI/CD Security Gate**:
   - Geração e execução de manifestos CI/CD para **GitHub Actions**, **GitLab CI**, **Azure DevOps** e **Bitbucket Pipelines**.
   - Webhooks com autenticação criptográfica **HMAC-SHA256**.

---

## 🏛️ Arquitetura do Sistema

```
                                +-----------------------------------------------+
                                |          Repositório GitHub / GitLab / CI     |
                                +-----------------------------------------------+
                                                        |
                                           (Gatilho Webhook / Evento CI)
                                                        v
+---------------------------------------------------------------------------------------------------------------+
| Camada de Backend & API REST (Node.js + Express + TypeScript)                                                 |
|                                                                                                               |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | /api/audit/analyze       |  | /api/webhooks/github     |  | /api/badge/svg            |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | /api/audit/ast-refactor  |  | /api/github/refactor-pr  |  | /api/audit/suggest        |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|                 |                             |                             |                                 |
|                 v                             v                             v                                 |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
|   | OSV.dev / RustSec API    |  | SSE Stream Broadcast     |  | Gemini AI Engine          |                   |
|   | & Motores Estáticos AST  |  | & GitHub REST Client     |  | (Bounded Context Seguro)  |                   |
|   +--------------------------+  +--------------------------+  +---------------------------+                   |
+---------------------------------------------------------------------------------------------------------------+
                                                        |
                                          (Server-Sent Events / JSON REST)
                                                        v
+---------------------------------------------------------------------------------------------------------------+
| Frontend Enterprise (React 18 + Vite + Tailwind CSS + Framer Motion)                                          |
|                                                                                                               |
|  [ Dashboard GRC ] [ SBOM Studio ] [ PQC Hub ] [ CI/CD Multi-Cloud ] [ Ledger Imutável SIEM ]                 |
|  [ AST Refactor Studio ] [ Code Review ] [ Teoria das Ondas ] [ Cluster 10k RPS Simulator ]                   |
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
   *(Opcional: configure sua `GEMINI_API_KEY` para enriquecimento por IA; o sistema conta com fallback determinístico completo).*

4. **Executar em Modo de Desenvolvimento**:
   ```bash
   npm run dev
   ```

5. **Executar Testes e Lint**:
   ```bash
   npm run lint
   npm test
   ```

6. **Compilar e Executar para Produção**:
   ```bash
   npm run build
   npm start
   ```

7. **Acessar a Plataforma**:
   Abra no seu navegador: `http://localhost:3000`

---

## ⚙️ Configuração do GitHub Actions CI/CD Gate

O repositório já inclui o pipeline automatizado em `.github/workflows/ci.yml`. Toda abertura de Pull Request ou push na branch `main` executa:

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
- **NIST FIPS 203, FIPS 204, FIPS 205** (Padrões Pós-Quânticos ML-KEM, ML-DSA e SLH-DSA)
- **OWASP CycloneDX v1.5 & ISO/IEC 5962 SPDX v2.3** (Padrões Oficiais de SBOM)
- **OASIS SARIF v2.1.0** (Static Analysis Results Interchange Format)
- **Common Event Format (CEF) & JSON-ND** (Ingestão SIEM)

---

## 📄 Licença

Distribuído sob a licença **MIT**. Consulte o arquivo de licença para mais informações.

---

<p align="center">
  <sub>Desenvolvido com excelência técnica por <strong>NEXAVOR-QUANTUM-AUDIT / RustShield Quantum</strong>.</sub>
</p>
