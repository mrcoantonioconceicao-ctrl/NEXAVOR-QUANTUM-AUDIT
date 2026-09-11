import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { SolanaSandboxCounter, IDL } from "../target/types/solana_sandbox_counter.ts";

export type { SolanaSandboxCounter };
export { IDL };

/**
 * Deriva deterministicamente o PDA (Program Derived Address) da conta UserCounter
 * utilizando a seed "counter" e a chave pública da autoridade.
 */
export function deriveCounterPda(
  authorityPublicKey: PublicKey,
  programId: PublicKey = new PublicKey(IDL.address)
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("counter"), authorityPublicKey.toBuffer()],
    programId
  );
}

/**
 * Interface do estado on-chain da conta de contador
 */
export interface UserCounterState {
  authority: PublicKey;
  count: anchor.BN;
  bump: number;
}

/**
 * SDK Cliente para interação com o Smart Contract SolanaSandboxCounter
 */
export class SolanaSandboxCounterClient {
  public program: Program<SolanaSandboxCounter>;
  public provider: anchor.AnchorProvider;

  constructor(provider: anchor.AnchorProvider, programId?: PublicKey) {
    this.provider = provider;
    const targetIdl = programId ? { ...IDL, address: programId.toBase58() } : IDL;
    this.program = new Program<SolanaSandboxCounter>(
      targetIdl,
      provider
    );
  }

  /**
   * Obtém o PDA para a autoridade conectada
   */
  public getCounterPda(authority?: PublicKey): [PublicKey, number] {
    const auth = authority || this.provider.wallet.publicKey;
    return deriveCounterPda(auth, new PublicKey(this.program.idl.address));
  }

  /**
   * Inicializa uma nova conta de contador no Solana
   */
  public async initialize(): Promise<string> {
    const authority = this.provider.wallet.publicKey;
    const [counterPda] = this.getCounterPda(authority);

    return await (this.program.methods as any)
      .initialize()
      .accounts({
        counter: counterPda,
        authority,
        systemProgram: SystemProgram.programId,
      })
      .rpc();
  }

  /**
   * Incrementa o contador da autoridade
   */
  public async increment(): Promise<string> {
    const authority = this.provider.wallet.publicKey;
    const [counterPda] = this.getCounterPda(authority);

    return await (this.program.methods as any)
      .increment()
      .accounts({
        counter: counterPda,
        authority,
      })
      .rpc();
  }

  /**
   * Consulta o estado atual da conta na blockchain
   */
  public async fetchCounter(authority?: PublicKey): Promise<UserCounterState> {
    const [counterPda] = this.getCounterPda(authority);
    const account = await (this.program.account as any).userCounter.fetch(counterPda);
    return {
      authority: account.authority,
      count: account.count,
      bump: account.bump,
    };
  }
}
