import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { expect } from "chai";

describe("solana_sandbox_counter", () => {
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.SolanaSandboxCounter as Program;

  it("Is initialized!", async () => {
    const tx = await program.methods.initialize().rpc();
    console.log("Transaction signature:", tx);
    expect(tx).to.be.a("string");
  });
});
