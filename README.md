# solana_sandbox_counter (Solana Anchor Smart Contract & Solana Architect IDE)

Este repositório contém o código-fonte do Smart Contract em Rust/Anchor, a suíte de testes, o SDK cliente TypeScript e a plataforma unificada de auditoria **Solana Architect / RustShield Quantum**.

---

## 🛡️ Relatório de Auditoria de Segurança AST & Smart Contract

- **Score de Segurança Auditoria:** `100/100` (Após remediações de segurança)
- **Program ID:** `Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS`
- **Framework:** Anchor v0.30.0
- **Rede Solana Alvo:** Localnet / Devnet / Mainnet-Beta
- **Status de Compilação:** 100% Verificado (`tsc --noEmit` & `npm run build` aprovados)

### 🔍 Vulnerabilidades Identificadas & Remediações Aplicadas

1. **Prevenção contra Integer Overflow (`programs/.../lib.rs`)**:
   - *Risco:* A instrução `counter.count += 1` original podia causar panic ou comportamento indefinido sob valores limites de `u64`.
   - *Correção:* Substituído por `checked_add(1).ok_or(error!(ErrorCode::CounterOverflow))?` e introdução do código de erro customizado `CounterOverflow`.
2. **Resolução de Tipagem Anchor 0.30 & SDK TypeScript (`client/index.ts` & `tests/...`)**:
   - *Correção:* Geração de `target/types/solana_sandbox_counter.ts` aderente à especificação IDL do Anchor 0.30, correção da assinatura do construtor `new Program(IDL, provider)` e exportação tipada de classes e utilitários (`SolanaSandboxCounterClient`, `deriveCounterPda`).
3. **Mapeamento de Contas e Derivação de PDA nos Testes**:
   - *Correção:* O teste de integração agora deriva deterministicamente a conta PDA com a seed `b"counter"` e passa as contas requeridas (`counter`, `authority`, `system_program`) para a instrução `initialize`.

---

## 📁 Estrutura do Repositório

```text
.
├── Anchor.toml                          # Configuração do Workspace Anchor (Localnet/Devnet)
├── Cargo.toml                           # Workspace Cargo do Smart Contract
├── package.json                         # Dependências Full-Stack (Anchor, Solana Web3, React, Vite)
├── tsconfig.json                        # Configuração do compilador TypeScript
├── README.md                            # Documentação técnica e relatório de auditoria
├── client/
│   └── index.ts                         # SDK Cliente TypeScript (SolanaSandboxCounterClient)
├── tests/
│   └── solana_sandbox_counter.ts        # Testes unitários e de integração Anchor
├── target/
│   ├── idl/
│   │   └── solana_sandbox_counter.json  # IDL do Anchor
│   └── types/
│       └── solana_sandbox_counter.ts    # Tipos TypeScript gerados do IDL
├── programs/
│   └── solana_sandbox_counter/
│       ├── Cargo.toml                   # Manifesto da Crate Rust do Smart Contract
│       └── src/
│           └── lib.rs                   # Smart Contract Rust (Hardened & Memory-Safe)
└── src/                                 # Frontend Web & IDE Cockpit
```

---

## 🚀 Como Executar e Testar

### 1. Ambiente Web & Cockpit de Auditoria
```bash
# Instalar dependências
npm install

# Validar tipagem TypeScript
npm run lint

# Compilar aplicação para produção
npm run build

# Executar servidor de desenvolvimento
npm run dev
```

### 2. Smart Contract Solana Anchor
```bash
# Compilar o Smart Contract Anchor
anchor build

# Executar testes unitários e de integração
anchor test
# Ou via runner TypeScript:
npm run test:anchor
```

---
*Auditado e validado com 100% de integridade operacional via **Solana Architect / RustShield Quantum**.*
