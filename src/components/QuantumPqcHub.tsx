import React, { useState } from 'react';
import {
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  Lock,
  Zap,
  Activity,
  Layers,
  ArrowRight,
  ShieldCheck,
  Key,
} from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface CryptographicAuditHubProps {
  report: SecurityAuditReport | null;
}

export const CryptographicAuditHub: React.FC<CryptographicAuditHubProps> = ({ report }) => {
  const [selectedAlgo, setSelectedAlgo] = useState<'aes_gcm' | 'chacha' | 'ed25519' | 'argon2'>('aes_gcm');

  const cryptoMetrics = report?.quantumMetrics || {
    quantumReadinessScore: 92,
    shorAlgorithmVulnerability: 'SAFE',
    groverResistanceBits: 256,
    detectedLegacyPrimitives: ['MD5', 'SHA-1', 'DES-CBC', 'RC4'],
    recommendedPqcReplacements: ['AES-256-GCM', 'ChaCha20-Poly1305', 'Ed25519', 'Argon2id'],
    constantTimeCompliance: true,
    entropySourceAudit: 'Hardware CSPRNG Verified (ring::rand::SystemRandom)',
  };

  const algos = {
    aes_gcm: {
      standard: 'NIST SP 800-38D / FIPS 197',
      name: 'AES-256-GCM (Authenticated Encryption with Associated Data)',
      purpose: 'Cifragem Autenticada de Dados em Trânsito e em Repouso (Zero Trust)',
      replaces: 'DES, 3DES, AES-CBC com padding oracle (CWE-327), RC4',
      rustCrate: 'aes-gcm = "0.10"',
      recipe: `// Cifragem Segura Autenticada AES-256-GCM com Validação de Tag de Integridade
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

pub fn encrypt_payload(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256Gcm::new(key_bytes.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bit Unique Nonce
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| "Falha de encriptação AEAD")?;
    
    let mut output = nonce.to_vec();
    output.extend_from_slice(&ciphertext);
    Ok(output)
}`,
    },
    chacha: {
      standard: 'RFC 8439 / TLS 1.3 Standard',
      name: 'ChaCha20-Poly1305 (Constant-Time Stream Cipher)',
      purpose: 'Cifragem de Alta Performance com Imunidade a Timing Attacks por Design',
      replaces: 'Cifras vulneráveis a ataques de canal lateral em hardware sem AES-NI',
      rustCrate: 'chacha20poly1305 = "0.10"',
      recipe: `// ChaCha20-Poly1305 com Execução Estritamente em Tempo Constante
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

pub fn encrypt_stream_safe(key_bytes: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new(key_bytes.into());
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let encrypted = cipher.encrypt(&nonce, data).map_err(|_| "Falha AEAD")?;
    
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&encrypted);
    Ok(payload)
}`,
    },
    ed25519: {
      standard: 'RFC 8032 / FIPS 186-5',
      name: 'Ed25519 (Edwards-curve Digital Signature Algorithm)',
      purpose: 'Assinatura Digital Rápida de Artefatos, Binários e Tokens de Autorização',
      replaces: 'Assinaturas fracas RSA-1024, DSA e curvas com parâmetros não auditados',
      rustCrate: 'ed25519-dalek = "2.1"',
      recipe: `// Assinatura e Verificação Segura de Binários via Ed25519
use ed25519_dalek::{Signer, SigningKey, VerifyingKey, Signature, Verifier};
use rand::rngs::OsRng;

pub fn sign_audit_binary(data: &[u8]) -> (Vec<u8>, [u8; 32]) {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let signature: Signature = signing_key.sign(data);
    let verifying_key: VerifyingKey = signing_key.verifying_key();
    
    (signature.to_bytes().to_vec(), verifying_key.to_bytes())
}`,
    },
    argon2: {
      standard: 'RFC 9106 / OWASP Password Storage Guide',
      name: 'Argon2id (Memory-Hard Key Derivation Function)',
      purpose: 'Hashing Seguro de Senhas e Derivação de Chaves Resistente a Ataques de GPU/ASIC',
      replaces: 'MD5, SHA-1, SHA-256 simples sem sal, bcrypt com custo obsoleto',
      rustCrate: 'argon2 = "0.5"',
      recipe: `// Derivação de Chaves Memory-Hard com Argon2id
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};

pub fn hash_credentials_securely(secret: &[u8]) -> Result<String, &'static str> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(secret, &salt).map_err(|_| "Erro no hash")?;
    Ok(hash.to_string())
}`,
    },
  };

  const currentAlgo = algos[selectedAlgo];

  return (
    <div className="space-y-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded-xl border border-zinc-800 bg-linear-to-r from-emerald-950/40 via-zinc-900 to-zinc-950 p-5 sm:p-6 shadow-xl">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2">
            <span className="flex h-6 items-center rounded-md bg-emerald-500/20 px-2 text-[10px] font-mono font-bold uppercase text-emerald-400 border border-emerald-500/30">
              NIST SP 800-38D & Zero Trust Architecture
            </span>
            <span className="text-xs text-zinc-400 font-mono">Modern Cryptographic Assurance</span>
          </div>
          <h2 className="text-xl sm:text-2xl font-bold font-mono text-white tracking-tight">
            Hub de Auditoria Criptográfica & Zero Trust (RustShield Core)
          </h2>
          <p className="text-xs sm:text-sm text-zinc-400 max-w-3xl">
            Inspeção rigorosa de primitivas de cifra, verificação de tempo constante (<code className="text-emerald-400">subtle::ConstantTimeEq</code>), auditoria de CSPRNGs e mitigação de vulnerabilidades OWASP A02 (Cryptographic Failures).
          </p>
        </div>

        {/* Top Metric Cards */}
        <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 space-y-1">
            <div className="text-xs text-emerald-300 font-mono">Postura Criptográfica</div>
            <div className="text-2xl font-bold font-mono text-white">
              {cryptoMetrics.quantumReadinessScore} / 100
            </div>
            <div className="text-[11px] text-zinc-400">
              {cryptoMetrics.quantumReadinessScore >= 80 ? 'Cifras Modernas em Conformidade' : 'Requer Substituição de Primitivas'}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-950/20 space-y-1">
            <div className="text-xs text-rose-300 font-mono">Primitivas Obsoletas Detectadas</div>
            <div className="text-2xl font-bold font-mono text-rose-400">
              {cryptoMetrics.detectedLegacyPrimitives.length}
            </div>
            <div className="text-[11px] text-zinc-400">
              {cryptoMetrics.detectedLegacyPrimitives.join(', ')}
            </div>
          </div>

          <div className="p-4 rounded-xl border border-indigo-500/30 bg-indigo-950/20 space-y-1">
            <div className="text-xs text-indigo-300 font-mono">Força Efetiva de Chave</div>
            <div className="text-2xl font-bold font-mono text-indigo-400">
              {cryptoMetrics.groverResistanceBits} bits
            </div>
            <div className="text-[11px] text-zinc-400">
              Proteção contra ataques de força bruta e colisões
            </div>
          </div>
        </div>
      </div>

      {/* Algorithm Tabs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        {[
          { id: 'aes_gcm', label: 'AES-256-GCM', badge: 'AEAD Standard' },
          { id: 'chacha', label: 'ChaCha20-Poly1305', badge: 'Constant-Time' },
          { id: 'ed25519', label: 'Ed25519 Dalek', badge: 'FIPS 186-5' },
          { id: 'argon2', label: 'Argon2id', badge: 'RFC 9106' },
        ].map((a) => (
          <button
            key={a.id}
            onClick={() => setSelectedAlgo(a.id as any)}
            className={`p-3.5 rounded-xl border font-mono transition-all text-left ${
              selectedAlgo === a.id
                ? 'border-emerald-500 bg-emerald-950/30 text-white shadow-lg'
                : 'border-zinc-800 bg-zinc-900/60 text-zinc-400 hover:bg-zinc-850 hover:text-zinc-200'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold truncate">{a.label}</span>
              <span className="text-[10px] text-emerald-400 px-1.5 py-0.5 rounded bg-emerald-950/50 border border-emerald-500/30">
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
              <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs font-mono font-bold text-emerald-400 border border-emerald-500/30">
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
          <div className="text-zinc-500 font-mono font-semibold">Substitui Primitivas Vulneráveis:</div>
          <div className="text-rose-300 font-mono">{currentAlgo.replaces}</div>
        </div>

        <pre className="p-4 bg-black/80 rounded-lg text-xs font-mono text-emerald-300 overflow-x-auto border border-zinc-900 leading-relaxed">
          {currentAlgo.recipe}
        </pre>
      </div>
    </div>
  );
};

// Aliasing for backwards-compatibility
export const QuantumPqcHub = CryptographicAuditHub;

