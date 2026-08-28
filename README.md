# 🛡️ RustShield Quantum — Enterprise DevSecOps, GRC, Supply Chain & PQC Suite

[![Enterprise Ready](https://img.shields.io/badge/Enterprise%20Grade-Production%20Ready%20v2.5-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://github.com)
[![Compliance Frameworks](https://img.shields.io/badge/Compliance-SOC2%20%7C%20ISO%2027001%20%7C%20NIST%20800--218-0284C7?style=for-the-badge&logo=security)](https://csrc.nist.gov)
[![SBOM Standards](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5%20%7C%20SPDX%20v2.3-9C27B0?style=for-the-badge&logo=json)](https://cyclonedx.org)
[![NIST PQC Standards](https://img.shields.io/badge/NIST%20PQC-FIPS%20203%20%7C%20FIPS%20204%20%7C%20FIPS%20205-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![AST + Gemini AI](https://img.shields.io/badge/AST%20%2B%20Gemini%20AI-Deterministic%20Refactor-FF6F00?style=for-the-badge&logo=google)](https://ai.google.dev)
[![Multi-Cloud CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20%7C%20GitLab%20%7C%20Azure%20%7C%20Bitbucket-3178C6?style=for-the-badge&logo=githubactions)](https://github.com)

---

## 📋 Visão Geral Executiva

O **RustShield Quantum (Q-Audit Enterprise)** é uma plataforma unificada de **Engenharia de Segurança de Software de Nível Enterprise**, combinando:
- **Governança, Risco & Conformidade (GRC)** com alinhamento a normas internacionais (**SOC 2 Type II, ISO/IEC 27001:2022, NIST SP 800-218, PCI-DSS v4.0, OWASP 2025**);
- **Quantificação Financeira de Risco por Modelo FAIR** (ALE, SLE, ARO e ROSI);
- **Software Bill of Materials (SBOM)** auditável em **CycloneDX v1.5** e **SPDX v2.3** com integridade SHA-256 e rastreabilidade SLSA Level 3;
- **Refatoração Determinística de Código Legado (AST + Google Gemini IA)** com abertura automática de **Pull Requests no GitHub**;
- **Hub de Transição Criptográfica Pós-Quântica (PQC)** conforme os padrões **NIST FIPS 203, FIPS 204 e FIPS 205**;
- **Trilha de Auditoria Imutável (Hash Chain Forense)** e streaming **SIEM (CEF / JSON-ND)** para Splunk, Datadog e ElasticSearch;
- **Studio de CI/CD Multi-Cloud & Webhooks em Tempo Real** com assinaturas criptográficas **HMAC-SHA256**.

Projetado para repositórios em **Rust**, **TypeScript/Node.js**, **Go**, **Python**, **C/C++** e contratos inteligentes **Anchor/Solana**.

---

## 🚀 Arquitetura & Módulos Enterprise

### 1. 🏛️ Governança, Risco & Conformidade (GRC Hub)
- **Matriz de Conformidade Automatizada**:
  - **SOC 2 Type II**: Controles de acesso lógico (CC6.1), gerenciamento de vulnerabilidades (CC6.6), resposta a incidentes (CC7.1) e gestão de mudanças (CC8.1).
  - **ISO/IEC 27001:2022**: Análise de vulnerabilidades técnicas (A.8.8), codificação segura (A.8.28) e segurança de cadeia de suprimentos (A.8.30).
  - **NIST SP 800-218 (SSDF v1.1)**: Práticas de codificação segura (PO.3.1), verificação automatizada por SAST/AST (PW.1.1) e identificação de vulnerabilidades (RV.1.1).
  - **PCI-DSS v4.0 & OWASP Top 10 (2025/2021)**: Proteção rigorosa contra Injection, Broken Access Control, falhas de criptografia e componentes defasados.
- **Quantificação de Risco Financeiro (Modelo FAIR)**:
  - Estimativa da **Perda Anual Esperada (ALE)** baseada no inventário de falhas e valuation de ativos digitais.
  - Projeção de **Retorno sobre Investimento em Segurança (ROSI)** com redução de até **92% do risco** via refatoração automatizada.
- **Gestão de SLAs de Remediação**:
  - Acompanhamento de prazos por criticidade: **Crítico (24 horas)**, **Alto (7 dias)**, **Médio (30 dias)**.

---

### 2. 📑 Software Bill of Materials (SBOM) de Padrão Aberto
- **OWASP CycloneDX v1.5 JSON**: Exportação com 1-clique contendo inventário completo de pacotes, hashes SHA-256, purls (`pkg:cargo/...`, `pkg:npm/...`), licenças e mapeamento de vulnerabilidades com CVSS v3.1 e CWEs.
- **ISO/IEC 5962 SPDX v2.3 JSON**: Documento de conformidade internacional de cadeia de suprimentos com hashes de arquivos de código auditados e informações de copyright.
- **Nível de Integridade SLSA Level 3**: Validação de procedência e integridade contra adulterações em tempo de build.

---

### 3. ⚛️ Hub de Transição Criptográfica Pós-Quântica (NIST PQC)
- **Avaliação contra os Algoritmos de Shor e Grover**:
  - Detecção de primitivas clássicas vulneráveis (**RSA**, **ECDSA**, **Diffie-Hellman**, **Ed25519**).
  - Verificação de resistência a Grover para chaves simétricas (128/256 bits).
- **Receitas Práticas de Migração FIPS**:
  - **FIPS 203 — ML-KEM (Kyber-768/1024)**: Troca de chaves e encapsulamento seguro contra escuta quântica futura (*Harvest Now, Decrypt Later*).
  - **FIPS 204 — ML-DSA (Dilithium-65/87)**: Assinatura digital pós-quântica de código, commits e tokens de autorização.
  - **FIPS 205 — SLH-DSA (SPHINCS+)**: Assinatura digital stateless baseada em árvores de Merkle.
  - **FN-DSA (Falcon)**: Assinaturas compactas de alta performance baseadas em reticulados.
- **Auditoria de Tempo Constante (`ConstantTimeEq`)**: Eliminação de ataques de canal lateral (*Timing Attacks*) em verificações criptográficas e manipulação de segredos.

---

### 4. 🔒 Trilha de Auditoria Imutável (Ledger Forense) & SIEM
- **Encadeamento Criptográfico SHA-256 (Hash Chain)**:
  - Registro sequencial à prova de adulteração (*Tamper-Proof*) para cada varredura, patch gerado, PR aberto e aprovação executiva.
  - Cada bloco contém `blockIndex`, `timestamp`, `action`, `actor`, `role`, `targetRepo`, `details`, `previousHash` e `hash`.
- **Exportação e Streaming SIEM**:
  - **CEF (Common Event Format)**: Formato nativo para integração com **Splunk**, **Datadog**, **Micro Focus ArcSight** e **QRadar**.
  - **JSON-ND (Newline Delimited JSON)**: Ingestão de alta velocidade para **ElasticSearch** e **Logstash**.
- **Simulador de Perfis RBAC Granular**:
  - **CISO / VP de Segurança**: Assinatura de homologação ISO 27001, supressão de riscos e bloqueio de merge CI/CD.
  - **Arquiteto de Segurança Líder**: Aprovação de refatoração AST, geração de patches 1-click e download de SBOM/SARIF.
  - **Auditor SecOps & Forense**: Exportação de SIEM e execução de testes Miri UB.
  - **Tech Lead / Engenheiro Senior**: Visualização de diffs legados e abertura de Pull Requests.
  - **Oficial de Conformidade / DPO**: Relatórios executivos PDF e auditoria GRC.

---

### 5. 🪄 Studio de Refatoração de Código Legado (AST + Gemini IA)
- **Camada Determinística (AST Parser)**: Mapeamento de nós problemáticos em blocos `unsafe`, dereferenciamento de ponteiros, `.unwrap()`, `static mut`, violações de tipagem e injeções.
- **Camada de IA Controlada (Google Gemini)**: Aplicação estrita de restrições sintáticas para gerar código limpo, idiomático, seguro e livre de alucinações.
- **1-Click Pull Request Automático com Commit Físico**:
  - Geração automatizada de branch isolada (`rustshield-legacy-refactor-[timestamp]`) com sanitização contra caracteres inválidos.
  - Conversão de conteúdo e commit físico do arquivo modificado via GitHub REST API com sanitização rigorosa de Base64 (`replace(/(\r\n|\n|\r)/g, "")`).
  - Condicionalidade de SHA para criação e atualização transparente de arquivos.
  - Abertura de Pull Request no repositório do cliente com parecer pericial e economia de esforço (~4.5h por arquivo).

---

### 6. 🌐 Studio CI/CD Multi-Cloud & Despacho de Webhooks
- **Manifestos Prontos para Produção**:
  - **GitHub Actions** (`.github/workflows/rustshield-audit.yml`) com upload para o GitHub Code Scanning (SARIF v2.1.0).
  - **GitLab CI/CD** (`.gitlab-ci.yml`) com artefatos de SAST e SBOM.
  - **Azure DevOps** (`azure-pipelines.yml`) com publicação de logs de análise.
  - **Bitbucket Pipelines** (`bitbucket-pipelines.yml`) com validação de PRs.
- **Despachador de Alertas Enterprise**: Envio de alertas assinados por **HMAC-SHA256** para canais SOC no **Slack**, **Discord**, **PagerDuty** e **Jira**.

---

### 7. 📑 Relatórios Executivos & Intercâmbio de Dados
- **Relatório Pericial em PDF**: Sumário executivo, pontuação de postura de segurança, matriz de riscos, parecer pericial e termo formal de homologação.
- **OASIS SARIF v2.1.0**: Compatibilidade nativa com GitHub Advanced Security e DefectDojo.

---

## 🛠️ Arquitetura do Sistema

```
                         +-----------------------------------------------+
                         |          Repositório GitHub / GitLab / CI     |
                         +-----------------------------------------------+
                                                 |
                                    (Gatilho Webhook / Evento CI)
                                                 v
+-----------------------------------------------------------------------------------------------+
| Servidor Node.js / Express (server.ts / routes.ts)                                            |
|                                                                                               |
|   +--------------------------+  +--------------------------+  +---------------------------+   |
|   | /api/audit/analyze       |  | /api/webhooks/github     |  | /api/badge/svg            |   |
|   +--------------------------+  +--------------------------+  +---------------------------+   |
|   | /api/audit/ast-refactor  |  | /api/github/refactor-pr  |  | /api/audit/suggest        |   |
|   +--------------------------+  +--------------------------+  +---------------------------+   |
|                 |                             |                             |                 |
|                 v                             v                             v                 |
|   +--------------------------+  +--------------------------+  +---------------------------+   |
|   | OSV.dev / RustSec API    |  | SSE Stream Broadcast     |  | Gemini AI Reasoning Engine|   |
|   | & AST Engine (DDD/Clean) |  | & GitHub REST API Commit |  | (Restrições Sintáticas)   |   |
|   +--------------------------+  +--------------------------+  +---------------------------+   |
+-----------------------------------------------------------------------------------------------+
                                                 | (Server-Sent Events / REST)
                                                 v
+-----------------------------------------------------------------------------------------------+
| Frontend Enterprise React 18 + Vite + Tailwind CSS                                            |
|                                                                                               |
|  [ Dashboard GRC ] [ SBOM Studio ] [ PQC Hub ] [ CI/CD Multi-Cloud ] [ Ledger Imutável SIEM ] |
|  [ AST Refactor Studio ] [ Code Review ] [ Teoria das Ondas ] [ Cluster 10k RPS Simulator ]   |
+-----------------------------------------------------------------------------------------------+
```

---

## 📦 Como Executar em Produção ou Localmente

### Pré-requisitos
- **Node.js**: v18 ou superior
- **npm**: v9 ou superior
- **Chave de API do Gemini**: Variável `GEMINI_API_KEY` (opcional, motor local determinístico incluso)

### Passo a Passo

1. **Clonar o Repositório**:
   ```bash
   git clone https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor.git
   cd Atolada-anchor
   ```

2. **Instalar Dependências**:
   ```bash
   npm install
   ```

3. **Configurar Variáveis de Ambiente**:
   ```bash
   cp .env.example .env
   ```

4. **Compilar e Iniciar em Modo de Produção**:
   ```bash
   npm run build
   npm start
   ```
   *Ou em modo de desenvolvimento:*
   ```bash
   npm run dev
   ```

5. **Acessar a Aplicação**:
   Abra [http://localhost:3000](http://localhost:3000) no seu navegador.

---

## 📄 Padrões e Certificações Suportadas

- **NIST SP 800-218** (Secure Software Development Framework - SSDF)
- **ISO/IEC 27001:2022** (Controles Anexo A: A.8.8, A.8.28, A.8.30)
- **SOC 2 Type II** (Trust Services Criteria CC6.1, CC6.6, CC7.1, CC8.1)
- **PCI-DSS v4.0** (Software Security Framework)
- **NIST FIPS 203, FIPS 204, FIPS 205** (Post-Quantum Cryptography)
- **OWASP CycloneDX v1.5** & **ISO/IEC 5962 SPDX v2.3** (SBOM)
- **OASIS SARIF v2.1.0** (Static Analysis Results Interchange Format)

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja `LICENSE` para mais detalhes.

---

<p align="center">
  <sub>Desenvolvido com padrão pericial por <strong>RustShield Quantum / Q-Audit Enterprise</strong>.</sub>
</p>

