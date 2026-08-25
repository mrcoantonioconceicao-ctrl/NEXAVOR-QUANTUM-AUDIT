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
];
