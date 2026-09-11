import type { Idl } from "@coral-xyz/anchor";

export type SolanaSandboxCounter = Idl & {
  address: "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS";
  metadata: {
    name: "solana_sandbox_counter";
    version: "0.1.0";
    spec: "0.1.0";
  };
  instructions: [
    {
      name: "initialize";
      discriminator: number[];
      accounts: any[];
      args: [];
    },
    {
      name: "increment";
      discriminator: number[];
      accounts: any[];
      args: [];
    }
  ];
  accounts: [
    {
      name: "userCounter";
      discriminator: number[];
    }
  ];
};

export const IDL: any = {
  address: "Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS",
  metadata: {
    name: "solana_sandbox_counter",
    version: "0.1.0",
    spec: "0.1.0"
  },
  instructions: [
    {
      name: "initialize",
      discriminator: [175, 175, 109, 31, 13, 152, 155, 237],
      accounts: [
        { name: "counter", writable: true },
        { name: "authority", writable: true, signer: true },
        { name: "systemProgram", address: "11111111111111111111111111111111" }
      ],
      args: []
    },
    {
      name: "increment",
      discriminator: [11, 18, 104, 9, 104, 174, 59, 33],
      accounts: [
        { name: "counter", writable: true },
        { name: "authority", signer: true }
      ],
      args: []
    }
  ],
  accounts: [
    {
      name: "userCounter",
      discriminator: [187, 85, 122, 104, 181, 135, 149, 143]
    }
  ]
};
