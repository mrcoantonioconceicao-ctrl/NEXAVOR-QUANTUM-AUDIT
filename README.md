# 🛡️ RustShield Quantum - Suíte Pericial de Auditoria de Segurança & PQC

[![Q-Audit Security Status](https://img.shields.io/badge/Q--Audit-96%2F100%20PASSED%20%E2%80%8B%20PQC%20READY-00C853?style=for-the-badge&logo=shield&logoColor=white)](https://github.com/user/repository)
[![NIST PQC Standards](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20FIPS%20204-00E676?style=for-the-badge&logo=lock)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-GitHub%20Webhooks%20Realtime-0284C7?style=for-the-badge&logo=githubactions)](https://github.com)
[![TypeScript](https://img.shields.io/badge/React%2018-Vite%20%7C%20Tailwind-3178C6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)

---

## 📋 Visão Geral

O **RustShield Quantum** (Q-Audit Enterprise) é uma plataforma avançada de auditoria de código, análise pericial de segurança e verificação de resiliência a ataques quânticos. Desenvolvido para inspecionar repositórios **Rust**, contratos inteligentes **Anchor/Solana** e bibliotecas críticas de infraestrutura, o sistema utiliza análise estática alimentada por inteligência artificial (Google Gemini API), verificação de vazamento de memória com Miri e testes de teoria de ondas criptográficas.

---

## 🚀 Principais Funcionalidades

### 1. 🔍 Auditoria Forense com Análise Gemini
- Ingestão direta de repositórios públicos e privados do GitHub ou envio de código-fonte em Rust.
- Detecção de vulnerabilidades críticas:
  - **Memory Corruption & Timing Leaks** em operações criptográficas.
  - **Unchecked Arithmetic & Underflows/Overflows** em cálculo de taxas e tokens.
  - **Account Validation Flaws** em programas Solana Anchor (falta de checagem `has_one` ou `signer`).
  - **Concorrência e Mutex Contention** em reatores assíncronos Tokio.
- Cálculo de Score Global de Segurança (0 a 100) e atribuição de Nota Executiva (`A+` a `F`).

### 2. ⚛️ Verificação de Resistência Pós-Quântica (PQC)
- Avaliação de algoritmos em relação aos padrões oficiais do **NIST**:
  - **ML-KEM (Kyber)**: Troca de chaves baseada em reticulados.
  - **ML-DSA (Dilithium)**: Assinatura digital pós-quântica.
- Identificação de primitivas clássicas vulneráveis (**RSA-2048**, **ECDSA P-256/secp256k1**, **Ed25519**) com alertas e planos de migração para PQC.

### 3. ⚡ Webhooks & Integração CI/CD em Tempo Real
- **Gatilhos Automáticos do GitHub**: Recebe eventos de `git push`, `pull_request`, `workflow_run` e `release`.
- **Validação HMAC SHA-256**: Autenticação segura de cabeçalhos `X-Hub-Signature-256`.
- **Server-Sent Events (SSE)**: Atualizações ao vivo no navegador assim que um commit é enviado e auditado.
- **Simulador de Push Events**: Painel integrado para testar o envio de payloads sem depender de um push real no GitHub.

### 4. 🏷️ Gerador de Badges para README.md
- Geração de selos interativos de status de auditoria em Markdown, HTML e SVG direto.
- Personalização de estilos (`for-the-badge`, `flat-square`, `flat`, `plastic`).
- Exibição dinâmica do Score e conformidade PQC.

### 5. 📊 Simulador de Estresse & Ondas Criptográficas (10k TPS)
- Simulação gráfica interativa de carga em nós de validação (10.000 TPS).
- Teste de fadiga de chave sob ataques de perturbação espectral e variação de latência em milissegundos.

### 6. 🛠️ Comparador de Diffs & Remediação
- Visualização estática de diffs (`ANTES` vs `DEPOIS`) aplicando parches de segurança e correções em código Rust.

### 7. 📑 Exportação de Relatório Pericial em PDF
- Geração de relatórios executivos em formato PDF, prontos para compliance, investidores e equipes de DevSecOps.

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
| express.js Node Server (server.ts)                                               |
|                                                                                  |
|   +-----------------------+   +-----------------------+   +------------------+   |
|   | /api/audit/analyze    |   | /api/webhooks/github  |   | /api/badge/svg   |   |
|   +-----------------------+   +-----------------------+   +------------------+   |
|               |                           |                        |             |
|               v                           v                        v             |
|   +-----------------------+   +-----------------------+   +------------------+   |
|   | Gemini API Auditor    |   | SSE Stream Broadcast  |   | Badge Generator  |   |
|   +-----------------------+   +-----------------------+   +------------------+   |
+----------------------------------------------------------------------------------+
                                           |
                                  (Server-Sent Events)
                                           v
+----------------------------------------------------------------------------------+
| Front-end React 18 + Vite + Tailwind CSS                                         |
|                                                                                  |
|  [ Dashboard ]  [ Webhooks CI/CD ]  [ Diffs ]  [ Testes 10k TPS ]  [ BPMN Workflow ]
+----------------------------------------------------------------------------------+
```

---

## 📦 Como Executar Localmente

### Pré-requisitos
- **Node.js**: v18 ou superior
- **npm**: v9 ou superior
- **Chave de API do Gemini**: Definida em `GEMINI_API_KEY` (opcional, fallback incluído)

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
   Crie um arquivo `.env` na raiz do projeto:
   ```env
   PORT=3000
   GEMINI_API_KEY=sua_chave_gemini_aqui
   ```

4. **Iniciar o Servidor em Modo de Desenvolvimento**:
   ```bash
   npm run dev
   ```

5. **Acessar no Navegador**:
   Abra [http://localhost:3000](http://localhost:3000)

---

## ⚓ Configuração de Webhook no GitHub

Para integrar a auditoria automática ao seu repositório GitHub:

1. Vá até as **Configurações (Settings)** do seu repositório no GitHub.
2. Acesse **Webhooks** &rarr; **Add webhook**.
3. Em **Payload URL**, insira o endpoint do servidor:
   `https://sua-url-de-deploy.app/api/webhooks/github?secret=sec_qaudit_9941a87b3c2d`
4. Selecione **Content type**: `application/json`.
5. Em **Secret**, digite seu segredo HMAC configurado no painel.
6. Escolha os eventos de **Pushes** e **Pull Requests**.
7. Clique em **Add webhook**.

---

## 📂 Estrutura de Arquivos

```
├── server.ts                    # Servidor Express & Rotas de API
├── server/
│   ├── routes.ts                # Controladores principais de análise e GitHub
│   ├── geminiAuditor.ts         # Integração com SDK Google Gemini
│   ├── webhooks.ts              # Handlers de Webhook do GitHub & SSE Stream
│   └── badgeGenerator.ts        # Gerador dinâmico de selos SVG
├── src/
│   ├── App.tsx                  # Componente Raiz React
│   ├── components/
│   │   ├── AuditDashboard.tsx   # Dashboard Principal com Score e Métricas
│   │   ├── WebhookConfigView.tsx# Painel de Controle de Webhooks & Simulador
│   │   ├── SecurityBadgeModal.tsx # Gerador de Badges em Markdown
│   │   ├── ScaleClusterDashboard.tsx # Simulador de Estresse 10k TPS
│   │   ├── AuditDiffComparator.tsx   # Visualizador de Diffs e Remediação
│   │   ├── Sidebar.tsx          # Menu de Navegação Lateral
│   │   └── TopBar.tsx           # Barra Superior da Aplicação
│   ├── domain/
│   │   ├── types.ts             # Definições de Tipos TypeScript
│   │   └── benchmarks.ts        # Casos de Teste de Benchmark
│   └── services/                # Serviços de Comunicação com APIs
├── package.json
└── README.md
```

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja `LICENSE` para mais detalhes.

---

<p align="center">
  <sub>Desenvolvido com ❤️ pela equipe de Segurança Pericial Q-Audit Enterprise.</sub>
</p>
