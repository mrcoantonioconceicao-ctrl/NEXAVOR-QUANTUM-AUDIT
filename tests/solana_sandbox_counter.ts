import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, SystemProgram } from "@solana/web3.js";
import { expect } from "chai";
import { SolanaSandboxCounter, IDL } from "../target/types/solana_sandbox_counter.ts";

describe("solana_sandbox_counter", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = new Program<SolanaSandboxCounter>(
    IDL,
    provider
  );
  const authority = provider.wallet;

  // Deriva o PDA para a conta de contador vinculada à autoridade
  const [counterPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("counter"), authority.publicKey.toBuffer()],
    program.programId
  );

  it("Is initialized!", async () => {
    try {
      const tx = await (program.methods as any)
        .initialize()
        .accounts({
          counter: counterPda,
          authority: authority.publicKey,
          systemProgram: SystemProgram.programId,
        })
        .rpc();

      console.log("Transaction signature (init):", tx);
      expect(tx).to.be.a("string");

      const counterAccount = await (program.account as any).userCounter.fetch(counterPda);
      expect(counterAccount.authority.toBase58()).to.equal(authority.publicKey.toBase58());
      expect(counterAccount.count.toNumber()).to.equal(0);
    } catch (err: any) {
      // Se a conta já estiver inicializada em testes subsequentes
      if (err?.message?.includes("already in use") || err?.toString()?.includes("custom program error: 0x0")) {
        console.log("Conta PDA já inicializada previamente.");
      } else {
        throw err;
      }
    }
  });

  it("Increments counter!", async () => {
    const prevAccount = await (program.account as any).userCounter.fetch(counterPda);
    const prevCount = prevAccount.count.toNumber();

    const tx = await (program.methods as any)
      .increment()
      .accounts({
        counter: counterPda,
        authority: authority.publicKey,
      })
      .rpc();

    console.log("Transaction signature (increment):", tx);
    expect(tx).to.be.a("string");

    const updatedAccount = await (program.account as any).userCounter.fetch(counterPda);
    expect(updatedAccount.count.toNumber()).to.equal(prevCount + 1);
  });
});
