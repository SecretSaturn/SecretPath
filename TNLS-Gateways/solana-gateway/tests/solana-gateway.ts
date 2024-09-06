import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaGateway } from "../target/types/solana_gateway";
import { keccak256, getBytes } from "ethers";
import * as web3 from "@solana/web3.js";
import { clusterApiUrl, Connection } from "@solana/web3.js";
import crypto from "crypto";

describe("solana-gateway", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const program = anchor.workspace.SolanaGateway as Program<SolanaGateway>;
  const provider = anchor.getProvider();
  const connection = new Connection(clusterApiUrl("devnet"), "confirmed");

  // PDAs
  let gatewayPDA: web3.PublicKey;
  let taskPDA: web3.PublicKey;

  before(async () => {
    // Derive PDAs
    [gatewayPDA] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("gateway_state")],
      program.programId
    );

    [taskPDA] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("task_state")],
      program.programId
    );
  });

  it("Initializes the program", async () => {
    let accountExists = false;
    try {
      await program.account.gatewayState.fetch(gatewayPDA);
      accountExists = true;
    } catch (err) {
      if (err.message.includes("Account does not exist or has no data")) {
        accountExists = false;
      }
    }

    if (!accountExists) {
      const tx = await program.methods
        .initialize()
        .accounts({
          owner: provider.wallet.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([provider.wallet.payer])
        .rpc();
      console.log("Initialized Account", tx);
    }
  });

  it("Increases task state size", async () => {
    for (let i = 2; i <= 30; i++) {
      const tx = await program.methods
        .increaseTaskState(new anchor.BN(i * 10240))
        .accounts({
          gatewayState: gatewayPDA,
          taskState: taskPDA,
          owner: provider.wallet.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .rpc();

      console.log("Reallocated Task State with size:", i * 10240);
    }
  });

  it("Increases task id", async () => {
    const taskId = 1;
    await program.methods
      .increaseTaskId(new anchor.BN(taskId))
      .accounts({
        gatewayState: gatewayPDA,
        owner: provider.wallet.publicKey,
      })
      .rpc();
    console.log("Task ID Increased:", taskId);
  });

  it("Performs task payout", async () => {
    const tx = await program.methods
      .payoutBalance()
      .accounts({
        gatewayState: gatewayPDA,
        owner: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    console.log("Payout completed:", tx);
  });

  it("Sends a task", async () => {
    const taskDestinationNetwork = "pulsar-3";
    const routingContract = "secret15n9rw7leh9zc64uqpfxqz2ap3uz4r90e0uz3y3";
    const routingCodeHash = "931a6fa540446ca028955603fa4b924790cd3c65b3893196dc686de42b833f9c";
    const handle = "request_random";
    const callbackGasLimit = 1000000;

    const data = JSON.stringify({ numWords: 10 });
    const nonce = crypto.randomBytes(12);

    const payload = {
      data,
      routing_info: routingContract,
      routing_code_hash: routingCodeHash,
      user_address: provider.publicKey.toBase58(),
      user_key: Buffer.from(new Uint8Array(4)).toString("base64"),
      callback_address: "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN",
      callback_selector: Buffer.from(new Uint8Array(4)).toString("base64"),
      callback_gas_limit: callbackGasLimit,
    };

    const payloadJson = JSON.stringify(payload);
    const plaintext = Buffer.from(payloadJson);

    const payloadHash = Buffer.from(getBytes(keccak256(plaintext)));
    const executionInfo = {
      userKey: Buffer.from(new Uint8Array(4)),
      userPubkey: Buffer.from(new Uint8Array(4)),
      routingCodeHash,
      taskDestinationNetwork,
      handle,
      nonce: Buffer.from(nonce),
      callbackGasLimit,
      payload: plaintext,
      payloadSignature: Buffer.from("AA="),
    };

    const tx = await program.methods
      .send(provider.publicKey, routingContract, executionInfo)
      .accounts({
        gatewayState: gatewayPDA,
        taskState: taskPDA,
        user: provider.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Task sent:", tx);
  });

  it("Performs post execution", async () => {
    const taskId = 1;
    const postExecutionInfo = {
      packetHash: Buffer.from(new Uint8Array(32)),
      callbackAddress: Buffer.from(new Uint8Array(32)),
      callbackSelector: Buffer.from(new Uint8Array(32)),
      callbackGasLimit: Buffer.from(new Uint8Array(4)),
      packetSignature: Buffer.from(new Uint8Array(65)),
      result: Buffer.from(new Uint8Array(32)),
    };

    const tx = await program.methods
      .postExecution(new anchor.BN(taskId), "SolDN", postExecutionInfo)
      .accounts({
        gatewayState: gatewayPDA,
        taskState: taskPDA,
        signer: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();

    console.log("Post execution completed:", tx);
  });

  it("Tests callback functionality", async () => {
    const taskId = 1;
    const result = Buffer.from("Test result");

    const tx = await program.methods
      .callbackTest(new anchor.BN(taskId), result)
      .accounts({
        secretpathGateway: provider.wallet.publicKey,
      })
      .rpc();

    console.log("Callback test completed:", tx);
  });
});
