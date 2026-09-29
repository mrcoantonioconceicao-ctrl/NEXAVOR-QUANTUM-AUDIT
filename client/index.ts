import crypto from 'node:crypto';

export interface SolanaTransactionRecord {
  signature: string;
  slot?: number;
  err?: unknown;
  memo?: string;
}

/**
 * Verificação segura de seleção e igualdade de assinatura de transação (Solana/Web3).
 * Implementa comparação em tempo constante com proteção estrita contra Timing Attacks (CWE-208)
 * e previne exceções RangeError por incompatibilidade de tamanho de buffers.
 */
export function verifySelectedTransaction(
  selectedTx: SolanaTransactionRecord | null | undefined,
  tx: SolanaTransactionRecord | null | undefined
): boolean {
  // Verificação segura compatível com strings/buffers:
  const sigA = Buffer.from(selectedTx?.signature || '', 'utf-8');
  const sigB = Buffer.from(tx?.signature || '', 'utf-8');
  const isSelected = sigA.length === sigB.length && crypto.timingSafeEqual(sigA, sigB);

  return isSelected;
}

export function safeCompareSignatures(sig1: string, sig2: string): boolean {
  const sigA = Buffer.from(sig1 || '', 'utf-8');
  const sigB = Buffer.from(sig2 || '', 'utf-8');
  return sigA.length === sigB.length && crypto.timingSafeEqual(sigA, sigB);
}
