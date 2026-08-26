# 🛡️ RustShield Quantum - Suíte Pericial de Auditoria de Segurança, Supply Chain & PQC

[![Q-Audit Security Status](https://img.shields.io/badge/Q--Audit-98%2F100%20PASSED%20%E2%80%8B%20PQC%20READY-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://github.com)
[![Supply Chain Guard](https://img.shields.io/badge/Supply%20Chain-RustSec%20%7C%20OSV.dev%20Live-0284C7?style=for-the-badge&logo=cargo)](https://osv.dev)
[![AST + Gemini AI Refactor](https://img.shields.io/badge/AST%20%2B%20Gemini-Legacy%20Refactor%20Studio-9C27B0?style=for-the-badge&logo=google)](https://ai.google.dev)
[![NIST PQC Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20FIPS%20204-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Webhooks%20Realtime-0284C7?style=for-the-badge&logo=githubactions)](https://github.com)
[![TypeScript](https://img.shields.io/badge/React%2018-Vite%20%7C%20Tailwind%20%7C%20Express-3178C6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)

---

## 📋 Visão Geral

O **RustShield Quantum (Q-Audit Enterprise)** é uma plataforma avançada de auditoria de código, segurança de cadeia de suprimentos (*Supply Chain*), análise pericial de segurança, refatoração de código legado guiada por AST + IA e verificação de resiliência a ataques quânticos. 

Projetado para inspecionar repositórios em **Rust**, **TypeScript/Node.js**, **Go**, **Python**, **C/C++** e contratos inteligentes **Anchor/Solana**, o sistema combina:
1. **Refatoração de Código Legado Guiada por AST + Gemini IA**: Leitura determinística da Árvore Sintática Abstrata (AST) para imposição de restrições estruturais invioláveis ao raciocínio da IA Generativa, refatorando código legado e abrindo Pull Requests automatizados.
2. **Sugestão de Patches Rust com IA na Bancada**: Geração sob demanda de correções idiomáticas Clean Code/SOA/DDD diretamente na bancada de revisão de código.
3. **Auditoria em Tempo Real de Dependências & CVEs**: Integração contínua via **OSV.dev**, **RustSec Advisory Database** e **GitHub Advisory Database** com 1-Click PR de atualização de dependências.
4. **Motor Estático Polyglot & AST**: Detecção pericial de falhas de memória (`unsafe`), pânicos não tratados (`.unwrap()`), injeções e falhas de concorrência.
5. **Modelagem Espectral & Teoria das Ondas**: Detecção precoce de Zero-Days e amortecimento Soliton.
6. **Auditoria de Prontidão Pós-Quântica (PQC)**: Conformidade com **NIST FIPS 203 (ML-KEM/Kyber)** e **FIPS 204 (ML-DSA/Dilithium)**.
7. **Orquestração BPMN 2.0 Auditável**: Fluxo de trabalho rastreável em 7 etapas com suporte a **GitHub Webhooks (HMAC SHA-256)** e **Server-Sent Events (SSE)**.

---

## 🚀 Principais Módulos & Funcionalidades

### 1. 🪄 Studio de Refatoração de Código Legado (AST + Gemini IA)
- **Camada Determinística (AST Parser - Bounded Context de Análise)**:
  - Módulo analítico estático que processa a Árvore Sintática Abstrata do arquivo (`.rs`, `.ts`, `.go`, `.c`, etc.), extraindo nós problemáticos: blocos `unsafe`, dereferenciamento de ponteiros brutos, `.unwrap()`/`.expect()`, estado mutável estático (`static mut`), injeções de código e violações de tipagem (`any`).
  - Estabelece restrições sintáticas estruturais invioláveis enviadas à IA Generativa para prevenir alucinações de sintaxe.
- **Camada de IA Controlada (Google Gemini AI Reasoning)**:
  - Processa estritamente o contexto dos nós mapeados pela AST e devolve o código-fonte limpo, idiomático e compilável.
  - Fornece parecer técnico pericial, resumo de diff e justificativa de engenharia em **Português (PT-BR)**.
- **1-Click Pull Request Automático de Refatoração**:
  - Gera automaticamente a branch isolada `rustshield-legacy-refactor-[timestamp]`, comita o arquivo refatorado e abre o Pull Request no repositório GitHub do cliente com o cálculo do esforço de engenharia evitado (~4.5h por arquivo).

### 2. 🛠️ Bancada de Code Review & Sugestão de Patches Rust com IA
- Botão dedicado **"Sugerir Patch Rust com IA Gemini"** integrado à bancada de revisão.
- Geração imediata de patches idiomáticos com alternador de visualização (Patch Padrão vs. Patch IA).
- Destaques arquiteturais explicando detalhadamente a aplicação de **Clean Code**, **SOA / DDD** e **Orquestração BPMN 2.0**.

### 3. 📦 Supply Chain & Auditoria de Manifestos em Tempo Real
- **Varredura Universal de Manifestos**:
  - **Rust (`Cargo.toml` / `Cargo.lock`)**: Consulta à base RustSec e crates.io, identificando vulnerabilidades de *unsoundness* e advisories ativas.
  - **Node.js / TypeScript (`package.json`)**: Detecção de CVEs e vulnerabilidades npm.
  - **Go (`go.mod`)**: Identificação de módulos defasados e vulnerabilidades no ecossistema Go.
  - **Python (`requirements.txt` / `pyproject.toml`)**: Varredura contra falhas em pacotes PyPI.
- **Remediação Automática com 1 Clique (GitHub Pull Requests)**:
  - Criação automatizada de branch (`rustshield-patch-xxxxxx`) e abertura de **Pull Request oficial no GitHub** com os patches corretivos de manifesto aplicados.
  - Remediação global em lote ou pontual por vulnerabilidade diretamente na tabela do dashboard.
  - Suporte a GitHub Personal Access Token (PAT) com permissão `repo` e modo simulação.
- **Motor de Severidade Ponderada CVSS v3.1 / CVSS v4.0**:
  - Cálculo de Score Geral calibrado e realista, sem alarmismo injustificado.
- **Painel Visual Categorizado de Dependências**:
  - Cálculo de risco e **CVSS 4.0** com barras visuais de gravidade.
  - Links diretos para os advisories oficiais no **OSV.dev** (com proxy batch `/api/audit/osv-batch`) e **GitHub Advisory Database**.
  - Detecção de defasagem de versão (*Major Behind*, *Deprecated*, *EOL*) com comandos de correção prontos para cópia (`cargo update`, `npm install`, `go get -u`).

### 4. ⚛️ Criptografia Pós-Quântica (NIST PQC)
- Avaliação de algoritmos contra algoritmos de **Shor** e **Grover**.
- Transição de primitivas clássicas vulneráveis (**RSA**, **ECDSA**, **Ed25519**) para padrões **ML-KEM** e **ML-DSA**.
- Métricas de prontidão criptográfica e análise de ataques de temporização (*Timing Attacks*).

### 5. 🌊 Teoria das Ondas & Previsão de 0-Day
- Cálculo de entropia espectral e matriz de ressonância de risco.
- Mapeamento de ondas construtivas de falhas e recomendação de **Amortecedores Soliton** com isolamento arquitetural.

### 6. ⚡ Webhooks & Integração CI/CD em Tempo Real
- **Recepção de Gatilhos do GitHub**: Suporte a `push`, `pull_request`, `workflow_run` e `release`.
- **Assinatura Criptográfica HMAC SHA-256**: Validação rigorosa do header `X-Hub-Signature-256`.
- **Server-Sent Events (SSE)**: Atualização instantânea da interface sem necessidade de polling.
- **Simulador Interativo de Eventos**: Teste de webhooks com payloads sintéticos customizáveis.

### 7. 📊 Simulador de Estresse & Cluster (10k TPS)
- Simulação gráfica de nós validadores sob alta taxa de requisições concorrentes.
- Monitoramento de latência e consumo de memória.

### 8. 📑 Exportação de Relatórios Executivos
- Exportação em **PDF Pericial** com sumário executivo, matriz de risco e roadmap de remediação.
- Exportação em formato padronizado **SARIF (Static Analysis Results Interchange Format)** para integração com GitHub Code Scanning e SonarQube.

---

## 🛠️ Arquitetura do Sistema

```
                         +-----------------------------------+
                         |      GitHub Repository / CI       |
                         +-----------------------------------+
                                            |
                                 (Webhook Push / Event)
                                            v
+----------------------------------------------------------------------------------+
| express.js Node Server (server.ts / routes.ts)                                   |
|                                                                                  |
|   +-----------------------+   +-----------------------+   +------------------+   |
|   | /api/audit/analyze    |   | /api/webhooks/github  |   | /api/badge/svg   |   |
|   +-----------------------+   +-----------------------+   +------------------+   |
|   | /api/audit/ast-refactor   | /api/github/refactor-pr  | /api/audit/suggest|   |
|   +-----------------------+   +-----------------------+   +------------------+   |
|               |                           |                        |             |
|               v                           v                        v             |
|   +-----------------------+   +-----------------------+   +------------------+   |
|   | OSV.dev / RustSec API |   | SSE Stream Broadcast  |   | Gemini AI Engine |   |
|   | & AST Engine (DDD)    |   | & GitHub REST API     |   | (Fallback Local) |   |
|   +-----------------------+   +-----------------------+   +------------------+   |
+----------------------------------------------------------------------------------+
                                            | (Server-Sent Events)
                                            v
+----------------------------------------------------------------------------------+
| Front-end React 18 + Vite + Tailwind CSS                                         |
|                                                                                  |
|  [ Dashboard ] [ AST Refactor Studio ] [ BPMN 7-Steps ] [ Webhooks ] [ Diffs ]   |
+----------------------------------------------------------------------------------+
```

---

## 📦 Como Executar Localmente

### Pré-requisitos
- **Node.js**: v18 ou superior
- **npm**: v9 ou superior
- **Chave de API do Gemini**: Variável `GEMINI_API_KEY` (opcional, motor local estático incluso)

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

4. **Iniciar o Servidor de Desenvolvimento**:
   ```bash
   npm run dev
   ```

5. **Acessar a Aplicação**:
   Abra [http://localhost:3000](http://localhost:3000) no seu navegador.

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja `LICENSE` para mais detalhes.

---

<p align="center">
  <sub>Desenvolvido com excelência pericial por <strong>RustShield Quantum / Q-Audit Enterprise</strong>.</sub>
</p>

