import { RepositoryMetadata, SourceFile } from './types.ts';

export interface BenchmarkCase {
  id: string;
  name: string;
  category: 'ZERO_DAY_SOLITON' | 'LEGACY_UNSAFE' | 'QUANTUM_CRYPTO' | 'CONCURRENCY_RACE' | 'FFI_LEAK';
  language: string;
  description: string;
  repo: RepositoryMetadata;
  files: SourceFile[];
}

export const BENCHMARK_CASES: BenchmarkCase[] = [
  {
    id: 'actix-legacy-cell-07',
    name: 'Actix-Web v0.7 Unsafe Cell Aliasing (Rust)',
    category: 'LEGACY_UNSAFE',
    language: 'Rust',
    description: 'Vulnerabilidade histórica onde o uso indevido de `UnsafeCell` violava a regra de unicidade de referências mutáveis (`&mut`), gerando aliasing mutável e Data Race sob alta concorrência.',
    repo: {
      owner: 'actix-archive',
      name: 'actix-web-legacy-cell',
      fullName: 'actix-archive/actix-web-legacy-cell',
      description: 'Legacy web server crate with UnsafeCell aliasing and manual pointer caching',
      stars: 8400,
      forks: 920,
      openIssues: 14,
      defaultBranch: 'master',
      language: 'Rust',
      url: 'https://github.com/actix-archive/actix-web-legacy-cell',
      fileCount: 3,
      totalTreeFiles: 12,
    },
    files: [
      {
        path: 'Cargo.toml',
        size: 240,
        language: 'Rust',
        content: `[package]
name = "actix-legacy-server"
version = "0.7.18"
edition = "2015"

[dependencies]
futures = "0.1.29"
tokio = "0.1.22"
bytes = "0.4.12"`,
      },
      {
        path: 'src/cell.rs',
        size: 1420,
        language: 'Rust',
        content: `use std::cell::UnsafeCell;
use std::rc::Rc;

// Código Legado Rust 2015 com violação de aliasing mutável
pub struct LegacyCloneableCell<T> {
    inner: Rc<UnsafeCell<T>>,
}

impl<T> LegacyCloneableCell<T> {
    pub fn new(val: T) -> Self {
        LegacyCloneableCell {
            inner: Rc::new(UnsafeCell::new(val)),
        }
    }

    // Insegurança: Retorna referência mutável sem exclusividade estática garantida!
    pub unsafe fn get_mut_unchecked(&self) -> &mut T {
        &mut *self.inner.get()
    }

    pub fn clone_reference(&self) -> Self {
        LegacyCloneableCell {
            inner: self.inner.clone(),
        }
    }
}

// Implementação insegura de Send/Sync forçada
unsafe impl<T> Send for LegacyCloneableCell<T> {}
unsafe impl<T> Sync for LegacyCloneableCell<T> {}`,
      },
      {
        path: 'src/lib.rs',
        size: 980,
        language: 'Rust',
        content: `mod cell;
pub use cell::LegacyCloneableCell;

pub fn execute_request_pipeline() {
    let shared = LegacyCloneableCell::new(vec![1, 2, 3, 4]);
    let shared2 = shared.clone_reference();

    // Criação de referências mutáveis concorrentes ilegais (Undefined Behavior)
    unsafe {
        let r1 = shared.get_mut_unchecked();
        let r2 = shared2.get_mut_unchecked();
        r1.push(5);
        r2.clear(); // Conflito de desalocação e realocação simultânea!
    }
}`,
      },
    ],
  },
  {
    id: 'python-ai-pipeline-rce',
    name: 'FastAPI & PyTorch Ingestion Gateway (Python)',
    category: 'ZERO_DAY_SOLITON',
    language: 'Python',
    description: 'Pipeline corporativo de inteligência artificial contendo desserialização não confiável de modelos via `pickle.loads`, injeção de comandos `os.system` e hash legado MD5.',
    repo: {
      owner: 'enterprise-ai-lab',
      name: 'fastapi-pytorch-gateway',
      fullName: 'enterprise-ai-lab/fastapi-pytorch-gateway',
      description: 'Production AI ingestion service with distributed model weights serialization and dynamic tensor execution',
      stars: 4200,
      forks: 510,
      openIssues: 8,
      defaultBranch: 'main',
      language: 'Python',
      url: 'https://github.com/enterprise-ai-lab/fastapi-pytorch-gateway',
      fileCount: 3,
      totalTreeFiles: 9,
    },
    files: [
      {
        path: 'requirements.txt',
        size: 190,
        language: 'Python',
        content: `fastapi==0.109.0
uvicorn==0.27.0
torch==2.1.2
pycryptodome==3.10.1
pyyaml==5.4.1`,
      },
      {
        path: 'app/server.py',
        size: 1650,
        language: 'Python',
        content: `import pickle
import os
import hashlib
from fastapi import FastAPI, Request, HTTPException

app = FastAPI(title="AI Model Ingestion Gateway")

# VULNERABILIDADE CRÍTICA: Desserialização RCE via pickle
@app.post("/api/v1/load-model-weights")
async def load_model_weights(request: Request):
    raw_payload = await request.body()
    try:
        # Permite execução remota de código (RCE) via payloads construídos com __reduce__
        tensor_weights = pickle.loads(raw_payload)
        return {"status": "SUCCESS", "parameters_loaded": len(tensor_weights)}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# VULNERABILIDADE: Injeção de Comando no Sistema Operacional
@app.get("/api/v1/gpu-diagnostics")
def run_gpu_diagnostics(device_id: str):
    # Concatenação direta no shell permite injeção de operadores ; rm -rf /
    os.system(f"nvidia-smi --id={device_id} --query-gpu=utilization.gpu --format=csv")
    return {"status": "DISPATCHED"}

# VULNERABILIDADE: Criptografia Fraca & Timing Attack
def authenticate_worker_token(incoming_token: str, secret_token: str) -> bool:
    h_in = hashlib.md5(incoming_token.encode()).hexdigest()
    h_sec = hashlib.md5(secret_token.encode()).hexdigest()
    # Comparação não constante sujeita a ataque de canal lateral
    return h_in == h_sec`,
      },
      {
        path: 'app/config.py',
        size: 620,
        language: 'Python',
        content: `import yaml

def load_system_manifest(filepath: str):
    with open(filepath, 'r') as f:
        # Inseguro: yaml.load sem SafeLoader instancia objetos Python arbitrários
        return yaml.load(f)`,
      },
    ],
  },
  {
    id: 'ts-microservice-auth-gateway',
    name: 'Node.js Express & TypeScript Auth Gateway',
    category: 'ZERO_DAY_SOLITON',
    language: 'TypeScript',
    description: 'Serviço de autenticação corporativo vulnerável a Poluição de Protótipo (`Object.assign`), validação cega de JWT (`jwt.decode`) e alocação desinicializada de buffers.',
    repo: {
      owner: 'fintech-core',
      name: 'node-typescript-auth-gateway',
      fullName: 'fintech-core/node-typescript-auth-gateway',
      description: 'Distributed SSO & Token validation gateway with high throughput session caching',
      stars: 3100,
      forks: 390,
      openIssues: 11,
      defaultBranch: 'main',
      language: 'TypeScript',
      url: 'https://github.com/fintech-core/node-typescript-auth-gateway',
      fileCount: 3,
      totalTreeFiles: 14,
    },
    files: [
      {
        path: 'package.json',
        size: 340,
        language: 'TypeScript',
        content: `{
  "name": "node-typescript-auth-gateway",
  "version": "1.8.0",
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^8.5.1",
    "crypto-js": "^4.1.1"
  }
}`,
      },
      {
        path: 'src/auth/jwtService.ts',
        size: 1850,
        language: 'TypeScript',
        content: `import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { exec } from 'node:child_process';

const router = express.Router();

// VULNERABILIDADE CRÍTICA: Bypass de autenticação com jwt.decode sem verificar assinatura
export function verifySessionToken(token: string) {
  // Apenas decodifica base64 sem validar assinatura com chave secreta
  const decoded = jwt.decode(token) as any;
  if (!decoded || !decoded.userId) {
    throw new Error('Token inválido');
  }
  return decoded;
}

// VULNERABILIDADE: Poluição de Protótipo (Prototype Pollution)
export function mergeUserSession(target: any, incomingPayload: any) {
  for (const key of Object.keys(incomingPayload)) {
    if (typeof incomingPayload[key] === 'object' && incomingPayload[key] !== null) {
      if (!target[key]) target[key] = {};
      mergeUserSession(target[key], incomingPayload[key]);
    } else {
      // Injeta propriedades globais no __proto__ ou constructor.prototype
      target[key] = incomingPayload[key];
    }
  }
  return target;
}

// VULNERABILIDADE: Memory Leak via Buffer.allocUnsafe
export function generateEphemeralNonce(size: number): Buffer {
  // Aloca sem zerar memória prévia, vazando dados de heap para a resposta
  return Buffer.allocUnsafe(size);
}`,
      },
    ],
  },
  {
    id: 'golang-distributed-raft',
    name: 'Distributed Raft Cluster & RPC Engine (Go)',
    category: 'CONCURRENCY_RACE',
    language: 'Go',
    description: 'Motor de consenso distribuído em Go com Data Race em map sem Mutex, injeção de SQL via `fmt.Sprintf` e uso de `unsafe.Pointer`.',
    repo: {
      owner: 'cloud-infrastructure',
      name: 'raft-consensus-engine-go',
      fullName: 'cloud-infrastructure/raft-consensus-engine-go',
      description: 'Distributed replicated log engine for 10k CCU microservices',
      stars: 5200,
      forks: 680,
      openIssues: 19,
      defaultBranch: 'main',
      language: 'Go',
      url: 'https://github.com/cloud-infrastructure/raft-consensus-engine-go',
      fileCount: 2,
      totalTreeFiles: 8,
    },
    files: [
      {
        path: 'go.mod',
        size: 150,
        language: 'Go',
        content: `module github.com/cloud-infrastructure/raft-consensus-engine-go

go 1.22.0`,
      },
      {
        path: 'raft/state_machine.go',
        size: 1750,
        language: 'Go',
        content: `package raft

import (
	"database/sql"
	"fmt"
	"sync"
	"unsafe"
)

type ShardedClusterState struct {
	// VULNERABILIDADE: Map acessado concorrentemente por goroutines sem sync.RWMutex
	nodeMetadata map[string]string
	wg           sync.WaitGroup
}

func (s *ShardedClusterState) RegisterNodeAsync(nodeID string, addr string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Dispara fatal error: concurrent map writes derrubando o processo
		s.nodeMetadata[nodeID] = addr
	}()
}

// VULNERABILIDADE: Injeção de SQL no Go driver
func (s *ShardedClusterState) QueryAuditLog(db *sql.DB, tenantID string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT id, action FROM audit_logs WHERE tenant_id = '%s'", tenantID)
	return db.Query(query)
}

// VULNERABILIDADE: Type confusion via unsafe.Pointer
func FastCastBytes(raw []byte) *uint64 {
	return (*uint64)(unsafe.Pointer(&raw[0]))
}`,
      },
    ],
  },
  {
    id: 'cpp-legacy-daemon',
    name: 'Embedded Network Gateway & Packet Parser (C/C++)',
    category: 'LEGACY_UNSAFE',
    language: 'C++',
    description: 'Gateway legado de pacotes contendo Buffer Overflow clássico em `strcpy`/`sprintf`, vulnerabilidade de Format String e Use-After-Free em ponteiros.',
    repo: {
      owner: 'embedded-systems-core',
      name: 'packet-parser-daemon',
      fullName: 'embedded-systems-core/packet-parser-daemon',
      description: 'High throughput low-latency networking daemon with raw memory buffers',
      stars: 1800,
      forks: 240,
      openIssues: 15,
      defaultBranch: 'main',
      language: 'C++',
      url: 'https://github.com/embedded-systems-core/packet-parser-daemon',
      fileCount: 2,
      totalTreeFiles: 6,
    },
    files: [
      {
        path: 'src/parser.cpp',
        size: 1980,
        language: 'C++',
        content: `#include <iostream>
#include <cstring>
#include <cstdio>

struct PacketHeader {
    char client_tag[32];
    int packet_type;
};

// VULNERABILIDADE CRÍTICA: Buffer Overflow via strcpy
void parse_client_packet(const char* raw_incoming_stream) {
    char local_stack_buf[64];
    // Não verifica o comprimento da string, sobrescrevendo o ponteiro de retorno (RIP)
    strcpy(local_stack_buf, raw_incoming_stream);
    
    // VULNERABILIDADE CRÍTICA: Format string attack
    printf(local_stack_buf);
}

// VULNERABILIDADE: Use-After-Free (UAF)
void process_and_free_payload(char* packet_data) {
    free(packet_data);
    // Ponteiro não aterrado: continua sendo referenciado em tarefas subsequentes
    std::cout << "Debug byte: " << packet_data[0] << std::endl;
}`,
      },
      {
        path: 'CMakeLists.txt',
        size: 280,
        language: 'C++',
        content: `cmake_minimum_required(VERSION 3.16)
project(PacketParserDaemon CXX)
set(CMAKE_CXX_STANDARD 17)
add_executable(packet_daemon src/parser.cpp)`,
      },
    ],
  },
  {
    id: 'solidity-defi-liquidity-vault',
    name: 'DeFi Staking & Liquidity Pool Vault (Solidity)',
    category: 'ZERO_DAY_SOLITON',
    language: 'Solidity',
    description: 'Smart Contract DeFi com vulnerabilidade de Reentrância no saque de fundos (`.call{value: ...}`) e autenticação via `tx.origin`.',
    repo: {
      owner: 'ethereum-defi-vault',
      name: 'liquidity-staking-contract',
      fullName: 'ethereum-defi-vault/liquidity-staking-contract',
      description: 'Decentralized multi-token liquidity pool with flashloan yield harvesting',
      stars: 4900,
      forks: 830,
      openIssues: 12,
      defaultBranch: 'main',
      language: 'Solidity',
      url: 'https://github.com/ethereum-defi-vault/liquidity-staking-contract',
      fileCount: 1,
      totalTreeFiles: 4,
    },
    files: [
      {
        path: 'contracts/LiquidityVault.sol',
        size: 1890,
        language: 'Solidity',
        content: `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract LiquidityVault {
    mapping(address => uint256) public userBalances;
    address public contractOwner;

    constructor() {
        contractOwner = msg.sender;
    }

    function deposit() external payable {
        userBalances[msg.sender] += msg.value;
    }

    // VULNERABILIDADE CRÍTICA: Reentrancy (Violação do padrão Checks-Effects-Interactions)
    function withdrawBalance() external {
        uint256 amountToWithdraw = userBalances[msg.sender];
        require(amountToWithdraw > 0, "Saldo insuficiente");

        // Transfere o valor ANTES de zerar o saldo
        // Permite que um contrato malicioso invoque withdrawBalance repetidamente no fallback()
        (bool sent, ) = msg.sender.call{value: amountToWithdraw}("");
        require(sent, "Falha na transferencia de ETH");

        // Estado atualizado tarde demais
        userBalances[msg.sender] = 0;
    }

    // VULNERABILIDADE: Autenticação com tx.origin sujeita a ataque de phishing
    function emergencyDrainFunds(address payable recipient) external {
        require(tx.origin == contractOwner, "Apenas o proprietario pode executar");
        recipient.transfer(address(this).balance);
    }
}`,
      },
    ],
  },
  {
    id: 'slippay-fintech-gateway',
    name: 'SlipPay 2.0 - High-Throughput Fintech Payment Gateway (TypeScript/Rust)',
    category: 'QUANTUM_CRYPTO',
    language: 'TypeScript',
    description: 'Gateway financeiro de pagamentos corporativos, liquidação PIX e boletos SlipPay com validação de Webhooks HMAC, processador criptográfico e motor Rust de alta performance.',
    repo: {
      owner: 'mrcoantonioconceicao-ctrl',
      name: 'SlipPay_2.0',
      fullName: 'mrcoantonioconceicao-ctrl/SlipPay_2.0',
      description: 'SlipPay 2.0 - Gateway de pagamentos escalável com liquidação instantânea, antifraude e engine nativa de criptografia',
      stars: 1240,
      forks: 180,
      openIssues: 3,
      defaultBranch: 'main',
      language: 'TypeScript',
      url: 'https://github.com/mrcoantonioconceicao-ctrl/SlipPay_2.0',
      fileCount: 4,
      totalTreeFiles: 16,
    },
    files: [
      {
        path: 'package.json',
        size: 420,
        language: 'TypeScript',
        content: `{
  "name": "slippay-payment-gateway",
  "version": "2.0.4",
  "dependencies": {
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "crypto-js": "^4.2.0",
    "dotenv": "^16.4.5"
  }
}`,
      },
      {
        path: 'src/server.ts',
        size: 1980,
        language: 'TypeScript',
        content: `import express, { Request, Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const app = express();
app.use(express.json());

// VULNERABILIDADE: Validação de Webhook suscetível a Timing Attack
export function verifySlipWebhookSignature(payload: string, signature: string, secret: string): boolean {
  const hmac = crypto.createHmac('sha256', secret);
  const digest = hmac.update(payload).digest('hex');
  // Comparação de string direta em vez de crypto.timingSafeEqual
  return digest === signature;
}

// VULNERABILIDADE: Desserialização de JWT sem verificação obrigatória de algoritmo
export function authenticateSlipMerchant(token: string, secretKey: string) {
  return jwt.verify(token, secretKey, {
    algorithms: ['HS256', 'none'] // Inseguro: permite bypass com algoritmo 'none'
  });
}

// VULNERABILIDADE: Geração de Nonce com entropia previsível
export function generateSlipTransactionId(): string {
  const randomSuffix = Math.random().toString(36).substring(2, 10);
  return 'SLIP-TX-' + Date.now() + '-' + randomSuffix;
}

app.post('/api/v2/payments/charge', (req: Request, res: Response) => {
  const { amount, customerId, currency } = req.body;
  if (!amount || amount <= 0) {
    return res.status(400).json({ error: 'Valor de cobrança inválido' });
  }
  const txId = generateSlipTransactionId();
  return res.json({ status: 'PROCESSING', transactionId: txId, currency: currency || 'BRL' });
});`,
      },
      {
        path: 'Cargo.toml',
        size: 310,
        language: 'Rust',
        content: `[package]
name = "slippay-crypto-core"
version = "2.0.0"
edition = "2021"

[dependencies]
ring = "0.16.20"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"`,
      },
      {
        path: 'src/core_engine.rs',
        size: 1450,
        language: 'Rust',
        content: `use std::slice;

// Motor nativo de serialização rápida de transações financeiras
pub struct SlipFastBuffer {
    raw_ptr: *mut u8,
    capacity: usize,
}

impl SlipFastBuffer {
    pub fn new(capacity: usize) -> Self {
        let mut mem = Vec::with_capacity(capacity);
        let raw_ptr = mem.as_mut_ptr();
        std::mem::forget(mem);
        SlipFastBuffer { raw_ptr, capacity }
    }

    // VULNERABILIDADE: Dereferenciamento inseguro de ponteiro sem verificação de limites
    pub unsafe fn write_transaction_bytes(&self, offset: usize, bytes: &[u8]) {
        let dest = self.raw_ptr.add(offset);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), dest, bytes.len());
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        slice::from_raw_parts(self.raw_ptr, self.capacity)
    }
}`,
      },
    ],
  },
  {
    id: 'solana-anchor-vault',
    name: 'Solana Anchor Smart Contract Vault (Rust/Web3)',
    category: 'ZERO_DAY_SOLITON',
    language: 'Rust',
    description: 'Smart Contract DeFi na rede Solana desenvolvido com o framework Anchor, contendo verificação de contas PDA, controle de saldo e proteção contra Cross-Program Invocations (CPI) maliciosas.',
    repo: {
      owner: 'mrcoantonioconceicao-ctrl',
      name: 'Atolada-anchor',
      fullName: 'mrcoantonioconceicao-ctrl/Atolada-anchor',
      description: 'Solana Anchor Protocol - Programa de cofres descentralizados de liquidez com contas PDA e verificação de signatários',
      stars: 890,
      forks: 140,
      openIssues: 2,
      defaultBranch: 'main',
      language: 'Rust',
      url: 'https://github.com/mrcoantonioconceicao-ctrl/Atolada-anchor',
      fileCount: 4,
      totalTreeFiles: 11,
    },
    files: [
      {
        path: 'Cargo.toml',
        size: 380,
        language: 'Rust',
        content: `[package]
name = "solana-anchor-vault"
version = "0.1.0"
edition = "2021"

[dependencies]
anchor-lang = "0.29.0"
anchor-spl = "0.29.0"
solana-program = "1.18.0"`,
      },
      {
        path: 'programs/solana-anchor-vault/src/lib.rs',
        size: 2150,
        language: 'Rust',
        content: `use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod solana_anchor_vault {
    use super::*;

    pub fn initialize_vault(ctx: Context<InitializeVault>, bump: u8) -> Result<()> {
        let vault = &mut ctx.accounts.vault_state;
        vault.owner = ctx.accounts.owner.key();
        vault.bump = bump;
        vault.total_staked = 0;
        Ok(())
    }

    pub fn deposit_funds(ctx: Context<DepositFunds>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::ZeroDepositAmount);
        
        let cpi_accounts = Transfer {
            from: ctx.accounts.user_token_account.to_account_info(),
            to: ctx.accounts.vault_token_account.to_account_info(),
            authority: ctx.accounts.owner.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
        token::transfer(cpi_ctx, amount)?;

        let vault = &mut ctx.accounts.vault_state;
        vault.total_staked = vault.total_staked.checked_add(amount).ok_or(VaultError::CalculationOverflow)?;
        Ok(())
    }

    // VULNERABILIDADE: Validação ausente de owner da conta destino em saques de emergência
    pub fn emergency_withdraw(ctx: Context<EmergencyWithdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault_state;
        // Inseguro: falta verificar se ctx.accounts.recipient coincide com o vault.owner estrito
        vault.total_staked = vault.total_staked.saturating_sub(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(init, payer = owner, space = 8 + 32 + 1 + 8)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DepositFunds<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub user_token_account: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault_token_account: Account<'info, TokenAccount>,
    pub owner: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct EmergencyWithdraw<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    /// CHECK: Conta de destino de emergência sem validação de assinatura estrita
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    pub owner: Signer<'info>,
}

#[account]
pub struct VaultState {
    pub owner: Pubkey,
    pub bump: u8,
    pub total_staked: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("O valor do deposito deve ser maior que zero.")]
    ZeroDepositAmount,
    #[msg("Estouro numerico detectado no calculo.")]
    CalculationOverflow,
}`,
      },
    ],
  },
  {
    id: 'plataforma-nexa-saas',
    name: 'Plataforma Nexa - Enterprise Cloud SaaS & Microservices (TypeScript)',
    category: 'CONCURRENCY_RACE',
    language: 'TypeScript',
    description: 'Plataforma de governança corporativa e orquestração de serviços em nuvem com pipeline distribuído, controle RBAC, autenticação multifator e logs de auditoria.',
    repo: {
      owner: 'mrcoantonioconceicao-ctrl',
      name: 'plataforma-nexa',
      fullName: 'mrcoantonioconceicao-ctrl/plataforma-nexa',
      description: 'Plataforma Nexa - Suíte corporativa multilocatária de nuvem, conformidade GRC e APIs distribuídas',
      stars: 1560,
      forks: 210,
      openIssues: 5,
      defaultBranch: 'main',
      language: 'TypeScript',
      url: 'https://github.com/mrcoantonioconceicao-ctrl/plataforma-nexa',
      fileCount: 3,
      totalTreeFiles: 18,
    },
    files: [
      {
        path: 'package.json',
        size: 450,
        language: 'TypeScript',
        content: `{
  "name": "plataforma-nexa-core",
  "version": "1.4.2",
  "dependencies": {
    "express": "^4.19.2",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.5",
    "bcrypt": "^5.1.1",
    "zod": "^3.23.4"
  }
}`,
      },
      {
        path: 'src/api/auth/rbac.ts',
        size: 1720,
        language: 'TypeScript',
        content: `import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface NexaUserSession {
  userId: string;
  tenantId: string;
  role: 'SUPERADMIN' | 'AUDITOR' | 'DEVELOPER' | 'VIEWER';
}

// VULNERABILIDADE: Poluição de contexto na validação de permissões de tenants
export function enforceTenantAuthorization(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Token de autenticação ausente' });
  }

  try {
    const decoded = jwt.decode(token) as NexaUserSession;
    // Falha: não valida a assinatura criptográfica antes de confiar no payload do tenant
    if (decoded && decoded.tenantId) {
      (req as any).user = decoded;
      return next();
    }
    return res.status(403).json({ error: 'Sessão corporativa inválida' });
  } catch (err) {
    return res.status(401).json({ error: 'Falha ao processar credencial de acesso' });
  }
}

// VULNERABILIDADE: Concorrência em cache de credenciais sem lock
const activeSessionsCache = new Map<string, number>();

export function recordUserHeartbeat(userId: string) {
  // Acesso concorrente sem lock distribuído pode corromper contadores em alta carga
  const count = activeSessionsCache.get(userId) || 0;
  activeSessionsCache.set(userId, count + 1);
}`,
      },
      {
        path: 'src/services/dataPipeline.ts',
        size: 1280,
        language: 'TypeScript',
        content: `import { Pool } from 'pg';

const pool = new Pool();

// VULNERABILIDADE: Interpolação de parâmetros gerando potencial Injeção de SQL
export async function fetchTenantAuditTrail(tenantId: string, filterCategory?: string) {
  let query = "SELECT id, event_type, created_at FROM audit_trail WHERE tenant_id = '" + tenantId + "'";
  
  if (filterCategory) {
    query += " AND category = '" + filterCategory + "'";
  }

  query += " ORDER BY created_at DESC LIMIT 100";
  return await pool.query(query);
}`,
      },
    ],
  },
];
