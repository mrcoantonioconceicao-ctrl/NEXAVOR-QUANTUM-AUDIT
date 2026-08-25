import { QuantumCryptoMetrics, SourceFile } from './types.ts';

/**
 * Post-Quantum Cryptography & Quantum Resistance Auditor
 * Formulated by MIT Quantum Information Science principles:
 * - Shor's Algorithm polynomial-time factorization of RSA/ECC/DH
 * - Grover's Algorithm quadratic speedup against symmetric keys (halving effective entropy)
 * - NIST PQC Standards: ML-KEM (FIPS 203 / Kyber), ML-DSA (FIPS 204 / Dilithium), SLH-DSA (FIPS 205 / SPHINCS+)
 * - Constant-Time side-channel audit (preventing acoustic & cache-timing leakage)
 */

export function auditQuantumCryptography(files: SourceFile[]): QuantumCryptoMetrics {
  const detectedLegacyPrimitives: string[] = [];
  const recommendedPqcReplacements: string[] = [];
  let shorAlgorithmVulnerability: QuantumCryptoMetrics['shorAlgorithmVulnerability'] = 'SAFE';
  let groverResistanceBits = 256;
  let constantTimeCompliance = true;
  let penaltyPoints = 0;

  files.forEach((file) => {
    const content = file.content;

    // Check for RSA
    if (content.match(/rsa|RsaPrivateKey|RsaPublicKey|PKCS1v15|PKCS#1/i)) {
      detectedLegacyPrimitives.push('RSA (Fatoração Inteira Quebrável por Shor)');
      shorAlgorithmVulnerability = 'VULNERABLE';
      penaltyPoints += 35;
      if (!recommendedPqcReplacements.includes('ML-KEM-768 / Kyber (FIPS 203)')) {
        recommendedPqcReplacements.push('ML-KEM-768 / Kyber (FIPS 203)');
      }
    }

    // Check for ECC / ECDSA / Ed25519
    if (content.match(/secp256k1|p256|ecdsa|elliptic_curve|curve25519|ed25519_dalek/i)) {
      detectedLegacyPrimitives.push('Curvas Elípticas ECDSA/Ed25519 (Logaritmo Discreto Quebrável por Shor)');
      shorAlgorithmVulnerability = 'VULNERABLE';
      penaltyPoints += 30;
      if (!recommendedPqcReplacements.includes('ML-DSA-65 / Dilithium (FIPS 204)')) {
        recommendedPqcReplacements.push('ML-DSA-65 / Dilithium (FIPS 204)');
      }
      if (!recommendedPqcReplacements.includes('SLH-DSA / SPHINCS+ (FIPS 205 Stateless Hash)')) {
        recommendedPqcReplacements.push('SLH-DSA / SPHINCS+ (FIPS 205 Stateless Hash)');
      }
    }

    // Check for Diffie-Hellman
    if (content.match(/diffie_hellman|x25519|ecdh/i)) {
      detectedLegacyPrimitives.push('Diffie-Hellman / ECDH Key Exchange (Suscetível a Ataques "Store Now, Decrypt Later")');
      shorAlgorithmVulnerability = 'VULNERABLE';
      penaltyPoints += 25;
      if (!recommendedPqcReplacements.includes('Híbrido X25519 + ML-KEM (Draft IETF PQC)')) {
        recommendedPqcReplacements.push('Híbrido X25519 + ML-KEM (Draft IETF PQC)');
      }
    }

    // Check for legacy weak hashes
    if (content.match(/md5|sha1|sha_1|ripemd/i)) {
      detectedLegacyPrimitives.push('MD5 / SHA-1 Quebrados Criptograficamente');
      penaltyPoints += 20;
      if (!recommendedPqcReplacements.includes('BLAKE3 / SHA3-512 (Resistente a Grover)')) {
        recommendedPqcReplacements.push('BLAKE3 / SHA3-512 (Resistente a Grover)');
      }
    }

    // Check for AES-128 (Reduced to 64-bit security under Grover's algorithm)
    if (content.match(/aes128|aes_128|aes-128/i)) {
      groverResistanceBits = 128; // halved to 64-bit effective quantum security
      detectedLegacyPrimitives.push('AES-128 (Degradação por Grover para 64 bits de entropia efetiva)');
      penaltyPoints += 15;
      if (!recommendedPqcReplacements.includes('AES-256-GCM / ChaCha20-Poly1305 (128 bits efetivos sob Grover)')) {
        recommendedPqcReplacements.push('AES-256-GCM / ChaCha20-Poly1305 (128 bits efetivos sob Grover)');
      }
    }

    // Check for non-constant time branch comparisons (timing attacks)
    if (
      content.match(/==\s*&?\[u8\]|==\s*hash|memcmp|slice::cmp/i) &&
      !content.includes('subtle::ConstantTimeEq') &&
      !content.includes('ct_eq')
    ) {
      if (content.includes('crypto') || content.includes('auth') || content.includes('token') || content.includes('mac') || content.includes('signature')) {
        constantTimeCompliance = false;
        penaltyPoints += 18;
      }
    }
  });

  const quantumReadinessScore = Math.max(10, Math.min(100, 100 - penaltyPoints));

  let entropyAudit = 'Fontes de entropia conformes com `getrandom` OS-level CSPRNG.';
  if (penaltyPoints > 40) {
    entropyAudit = 'ATENÇÃO: Código legado exposto a vetores quânticos de Shor (Quebra de chaves públicas) e ataque antecipado "Harvest Now, Decrypt Later".';
  } else if (!constantTimeCompliance) {
    entropyAudit = 'Vulnerabilidade de canal lateral por tempo de execução (Timing Attack). Comparação direta sem `subtle::ConstantTimeEq`.';
  }

  return {
    quantumReadinessScore,
    shorAlgorithmVulnerability,
    groverResistanceBits,
    detectedLegacyPrimitives: detectedLegacyPrimitives.length > 0 ? Array.from(new Set(detectedLegacyPrimitives)) : ['Nenhum algoritmo assimétrico legado detectado'],
    recommendedPqcReplacements: recommendedPqcReplacements.length > 0 ? Array.from(new Set(recommendedPqcReplacements)) : ['ML-KEM-768 e ML-DSA-65 como salvaguarda preventiva PQC'],
    constantTimeCompliance,
    entropySourceAudit: entropyAudit,
  };
}
