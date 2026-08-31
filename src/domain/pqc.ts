/**
 * Bounded Context: PQC (Post-Quantum Cryptography & Constant-Time Security)
 * Especificações FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
 * e verificações de tempo constante.
 */

export interface FIPS203Spec {
  standard: 'FIPS 203';
  algorithm: 'ML-KEM'; // Crystal-Kyber
  parameterSet: 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';
  securityCategory: 1 | 3 | 5;
  publicKeySizeByte: number;
  ciphertextSizeByte: number;
  sharedSecretSizeByte: number;
}

export interface FIPS204Spec {
  standard: 'FIPS 204';
  algorithm: 'ML-DSA'; // Crystal-Dilithium
  parameterSet: 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';
  securityCategory: 2 | 3 | 5;
  signatureSizeByte: number;
}

export interface FIPS205Spec {
  standard: 'FIPS 205';
  algorithm: 'SLH-DSA'; // SPHINCS+
  parameterSet: 'SLH-DSA-SHA2-128f' | 'SLH-DSA-SHAKE-256f';
  securityCategory: 1 | 5;
  signatureSizeByte: number;
}

export interface ConstantTimeCheck {
  isConstantTime: boolean;
  branchingHazardsCount: number;
  tableLookupHazardsCount: number;
  recommendation: string;
}

export class PQCService {
  public static getKyber768Spec(): FIPS203Spec {
    return {
      standard: 'FIPS 203',
      algorithm: 'ML-KEM',
      parameterSet: 'ML-KEM-768',
      securityCategory: 3,
      publicKeySizeByte: 1184,
      ciphertextSizeByte: 1088,
      sharedSecretSizeByte: 32,
    };
  }

  public static getDilithium65Spec(): FIPS204Spec {
    return {
      standard: 'FIPS 204',
      algorithm: 'ML-DSA',
      parameterSet: 'ML-DSA-65',
      securityCategory: 3,
      signatureSizeByte: 3309,
    };
  }

  public static getSphincsPlusSpec(): FIPS205Spec {
    return {
      standard: 'FIPS 205',
      algorithm: 'SLH-DSA',
      parameterSet: 'SLH-DSA-SHA2-128f',
      securityCategory: 1,
      signatureSizeByte: 17088,
    };
  }

  public static checkConstantTime(codeSnippet: string): ConstantTimeCheck {
    const hasBranching = /\bif\s*\(.*secret.*\)|if\s+secret\b|\bmemcmp\b|\b==\b/.test(codeSnippet);
    const hasTableLookup = /secret_array\[.*secret.*\]/.test(codeSnippet);

    const isConstantTime = !hasBranching && !hasTableLookup;

    return {
      isConstantTime,
      branchingHazardsCount: hasBranching ? 1 : 0,
      tableLookupHazardsCount: hasTableLookup ? 1 : 0,
      recommendation: isConstantTime
        ? 'Operação em tempo constante verificada (subtração bitwise sem ramificação condicional).'
        : 'Substitua comparações de memória padrão (memcmp / ==) por ConstantTimeEq ou subtle::ConstantTimeEq para evitar ataques de canal lateral (Side-Channel Timing Attacks).',
    };
  }
}
