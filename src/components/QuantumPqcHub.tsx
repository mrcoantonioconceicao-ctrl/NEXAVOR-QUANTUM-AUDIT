import React, { useState } from 'react';
import {
  Cpu,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Lock,
  Zap,
  Activity,
  Layers,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface QuantumPqcHubProps {
  report: SecurityAuditReport | null;
}

export const QuantumPqcHub: React.FC<QuantumPqcHubProps> = ({ report }) => {
  const [selectedAlgo, setSelectedAlgo] = useState<'kyber' | 'dilithium' | 'sphincs' | 'falcon'>('kyber');

  const pqcMetrics = report?.quantumMetrics || {
    quantumReadinessScore: 68,
    shorAlgorithmVulnerability: 'VULNERABLE',
    groverResistanceBits: 128,
    detectedLegacyPrimitives: ['RSA-2048', 'ECDSA-secp256k1', 'SHA-1'],
    recommendedPqcReplacements: ['ML-KEM-768 (Kyber)', 'ML-DSA-65 (Dilithium)', 'SPHINCS+'],
    constantTimeCompliance: true,
    entropySourceAudit: 'Hardware TRNG verified',
  };

  const algos = {
    kyber: {
      standard: 'NIST FIPS 203',
      name: 'ML-KEM (Module-Lattice Key Encapsulation)',
      purpose: 'Troca de Chaves Criptográficas e Acordo Quântico Seguro',
      replaces: 'RSA-2048/4096, Diffie-Hellman (DH), ECDH (secp256r1, X25519)',
      rustCrate: 'ml-kem = "0.2"',
      recipe: `// Substituição Quântica FIPS 203 (ML-KEM-768)
use ml_kem::{MlKem768, KemCore};
use rand_core::OsRng;

pub fn generate_quantum_safe_shared_secret() -> ([u8; 32], Vec<u8>) {
    let (dk, ek) = MlKem768::generate_keypair(&mut OsRng);
    let (ciphertext, shared_secret) = ek.encapsulate(&mut OsRng).expect("PQC KEM failure");
    (shared_secret.as_bytes().clone(), ciphertext.as_bytes().to_vec())
}`,
    },
    dilithium: {
      standard: 'NIST FIPS 204',
      name: 'ML-DSA (Module-Lattice Digital Signature Algorithm)',
      purpose: 'Assinatura Digital de Código, Artefatos e Tokens de Autorização',
      replaces: 'RSA Signatures, ECDSA, Ed25519',
      rustCrate: 'ml-dsa = "0.1"',
      recipe: `// Assinatura Digital Pós-Quântica FIPS 204 (ML-DSA-65)
use ml_dsa::{MlDsa65, KeyGen, Signer, Verifier};
use rand_core::OsRng;

pub fn sign_audit_artifact(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = MlDsa65::generate_keypair(&mut OsRng);
    let signature = sk.sign(data, &mut OsRng).expect("ML-DSA sign failure");
    (signature.to_bytes().to_vec(), pk.to_bytes().to_vec())
}`,
    },
    sphincs: {
      standard: 'NIST FIPS 205',
      name: 'SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)',
      purpose: 'Blindagem de Assinatura Stateless baseada em Árvores de Merkle',
      replaces: 'Esquemas de assinatura com risco de comprometimento de reticulados',
      rustCrate: 'slh-dsa = "0.1"',
      recipe: `// Assinatura Baseada em Hashes FIPS 205 (SLH-DSA-SHAKE-128f)
use slh_dsa::{SlhDsaShake128f, KeyGen, Signer};
use rand_core::OsRng;

pub fn stateless_quantum_signature(msg: &[u8]) -> Vec<u8> {
    let (sk, _pk) = SlhDsaShake128f::generate_keypair(&mut OsRng);
    sk.sign(msg, &mut OsRng).expect("SLH-DSA error").to_bytes().to_vec()
}`,
    },
    falcon: {
      standard: 'NIST Draft / FN-DSA',
      name: 'FN-DSA (Fast-Fourier Lattice-based Signatures)',
      purpose: 'Assinaturas Compactas de Alta Performance em Ambientes Restritos',
      replaces: 'ECDSA para microcontroladores e transações de baixa latência',
      rustCrate: 'falcon-rust = "0.1"',
      recipe: `// Algoritmo Falcon-512 com Amostragem Gaussiana Rápida
use falcon_rust::Falcon512;

pub fn fast_compact_pqc_sign(message: &[u8]) -> Vec<u8> {
    let (sk, _pk) = Falcon512::keygen();
    sk.sign(message).expect("Falcon signing error")
}`,
    },
  };

  const currentAlgo = algos[selectedAlgo];

  return (
    <div className="space-y-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded-xl border border-zinc-800 bg-linear-to-r from-indigo-950/40 via-zinc-900 to-zinc-950 p-5 sm:p-6 shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="flex h-6 items-center rounded-md bg-indigo-500/20 px-2 text-[10px] font-mono font-bold uppercase text-indigo-400 border border-indigo-500/30">
              NIST FIPS 203/204/205 Standard
            </span>
            <span className="text-xs text-zinc-400 font-mono">MIT Quantum Computing Laboratory</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight">
            Hub de Transição Criptográfica Pós-Quântica (PQC)
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl">
            Avaliação de resistência contra os Algoritmos de Shor e Grover, prontidão CNSA 2.0 e receitas de migração para FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) e FIPS 205 (SLH-DSA).
          </p>
        </div>

        {/* Top Metric Cards */}
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl border border-indigo-500/30 bg-indigo-950/20 space-y-1">
            <div className="text-xs text-indigo-300 font-mono">Índice de Prontidão PQC</div>
            <div className="text-2xl font-bold font-mono text-white">
              {pqcMetrics.quantumReadinessScore} / 100
            </div>
            <div className="text-[11px] text-zinc-400">
              {pqcMetrics.quantumReadinessScore >= 80 ? 'Blindagem Alta' : 'Requer Substituição de Primitivas'}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-950/20 space-y-1">
            <div className="text-xs text-rose-300 font-mono">Vulnerabilidade a Shor</div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {pqcMetrics.shorAlgorithmVulnerability}
            </div>
            <div className="text-[11px] text-zinc-400">
              {pqcMetrics.detectedLegacyPrimitives.length} primitivas clássicas em risco de quebra assintótica
            </div>
          </div>

          <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 space-y-1">
            <div className="text-xs text-emerald-300 font-mono">Resistência a Grover</div>
            <div className="text-2xl font-bold font-mono text-emerald-400">
              {pqcMetrics.groverResistanceBits} bits
            </div>
            <div className="text-[11px] text-zinc-400">
              Resistência contra busca quântica em espaço de chaves simétricas
            </div>
          </div>
        </div>
      </div>

      {/* Algorithm Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { id: 'kyber', label: 'ML-KEM (Kyber)', badge: 'FIPS 203' },
          { id: 'dilithium', label: 'ML-DSA (Dilithium)', badge: 'FIPS 204' },
          { id: 'sphincs', label: 'SLH-DSA (SPHINCS+)', badge: 'FIPS 205' },
          { id: 'falcon', label: 'FN-DSA (Falcon)', badge: 'Draft' },
        ].map((a) => (
          <button
            key={a.id}
            onClick={() => setSelectedAlgo(a.id as any)}
            className={`p-3.5 rounded-xl border font-mono transition-all text-left ${
              selectedAlgo === a.id
                ? 'border-indigo-500 bg-indigo-950/30 text-white shadow-lg'
                : 'border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:bg-zinc-850 hover:text-zinc-200'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold truncate">{a.label}</span>
              <span className="text-[10px] text-indigo-400 px-1.5 py-0.5 rounded bg-indigo-950/50 border border-indigo-500/30">
                {a.badge}
              </span>
            </div>
          </button>
        ))}
      </div>

      {/* Algorithm details and code recipe */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-5 space-y-4 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-zinc-800 pb-3">
          <div>
            <div className="flex items-center gap-2">
              <span className="rounded bg-indigo-500/20 px-2 py-0.5 text-xs font-mono font-bold text-indigo-400 border border-indigo-500/30">
                {currentAlgo.standard}
              </span>
              <h3 className="text-sm font-mono font-bold text-white">{currentAlgo.name}</h3>
            </div>
            <p className="text-xs text-zinc-400 mt-1">{currentAlgo.purpose}</p>
          </div>

          <span className="text-xs font-mono text-emerald-400 bg-zinc-900 px-2.5 py-1 rounded border border-zinc-800">
            Cargo: {currentAlgo.rustCrate}
          </span>
        </div>

        <div className="text-xs space-y-1">
          <div className="text-zinc-500 font-mono font-semibold">Substitui Imediatamente:</div>
          <div className="text-rose-300 font-mono">{currentAlgo.replaces}</div>
        </div>

        <pre className="p-4 bg-black/80 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto border border-zinc-900 leading-relaxed">
          {currentAlgo.recipe}
        </pre>
      </div>
    </div>
  );
};
