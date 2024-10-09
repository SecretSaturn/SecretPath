import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaGateway } from "../target/types/solana_gateway";
import { keccak256, getBytes } from "ethers";
import * as web3 from "@solana/web3.js";
import { clusterApiUrl, Connection } from "@solana/web3.js";
import crypto from "crypto";
import * as assert from "assert";

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
    // Fetch the current taskId from the gatewayState account
    const gatewayState = await program.account.gatewayState.fetch(gatewayPDA);
    const currentTaskId = gatewayState.taskId.toNumber();
  
    // Increase the taskId by 1
    const newTaskId = currentTaskId + 1;
  
    // Call the increaseTaskId method with the new taskId
    await program.methods
      .increaseTaskId(new anchor.BN(newTaskId))
      .accounts({
        gatewayState: gatewayPDA,
        owner: provider.wallet.publicKey,
      })
      .rpc();
    console.log("Task ID Increased to:", newTaskId);
  
    // Fetch the updated gatewayState to verify the taskId has been updated
    const updatedGatewayState = await program.account.gatewayState.fetch(gatewayPDA);
    const updatedTaskId = updatedGatewayState.taskId.toNumber();
  
    // Check that the taskId has been updated correctly
    assert.strictEqual(
      updatedTaskId,
      newTaskId,
      `Expected taskId to be ${newTaskId}, but found ${updatedTaskId}`
    );
  });

  it("Performs task payout", async () => {
    // Fetch initial balances
    const ownerInitialBalance = await connection.getBalance(provider.wallet.publicKey);
    const gatewayInitialBalance = await connection.getBalance(gatewayPDA);
  
    console.log("Owner balance before funding:", ownerInitialBalance);
    console.log("Gateway balance before funding:", gatewayInitialBalance);
  
    // Create a transfer instruction to fund the gatewayState account
    const transferIx = web3.SystemProgram.transfer({
      fromPubkey: provider.wallet.publicKey,
      toPubkey: gatewayPDA,
      lamports: 10_000_000, // 0.01 SOL
    });
  
    // Send the transaction
    const txSig = await provider.sendAndConfirm(new web3.Transaction().add(transferIx), undefined, 'confirmed');
    console.log("Transferred lamports to gatewayState:", txSig);
  
    // Fetch balances after funding
    const ownerAfterFundingBalance = await connection.getBalance(provider.wallet.publicKey);
    const gatewayAfterFundingBalance = await connection.getBalance(gatewayPDA);
  
    console.log("Owner balance after funding:", ownerAfterFundingBalance);
    console.log("Gateway balance after funding:", gatewayAfterFundingBalance);
  
    // Call the payoutBalance function
    const payoutTx = await program.methods
      .payoutBalance()
      .accounts({
        gatewayState: gatewayPDA,
        owner: provider.wallet.publicKey,
        systemProgram: web3.SystemProgram.programId,
      })
      .rpc();
    console.log("Payout completed:", payoutTx);
  
    // Fetch balances after payout
    const ownerFinalBalance = await connection.getBalance(provider.wallet.publicKey);
    const gatewayFinalBalance = await connection.getBalance(gatewayPDA);
  
    console.log("Owner final balance:", ownerFinalBalance);
    console.log("Gateway final balance:", gatewayFinalBalance);
  
    // Verify that owner's balance increased (minus transaction fees)
    assert.ok(
      ownerFinalBalance > ownerAfterFundingBalance, // accounting for fees
      "Owner's balance did not increase"
    );
  
    // Verify that gateway's balance decreased appropriately
    const rentExemptMinimum = await connection.getMinimumBalanceForRentExemption(
      (await connection.getAccountInfo(gatewayPDA)).data.length
    );
    assert.ok(
      gatewayFinalBalance <= rentExemptMinimum,
      "Gateway's balance did not decrease to rent-exempt minimum"
    );
  });

  it("Sends a task", async () => {
    const taskDestinationNetwork = "pulsar-3";
    const routingContract = "secret15n9rw7leh9zc64uqpfxqz2ap3uz4r90e0uz3y3";
    const routingCodeHash = "931a6fa540446ca028955603fa4b924790cd3c65b3893196dc686de42b833f9c";
    const handle = "request_random";
    const callbackGasLimit = 1000000;

    const data = JSON.stringify({ numWords: 10 });
    const nonce = Buffer.from(new Uint8Array(12));

    // This is an empty callback for the sake of having a callback in the sample code.
    // Here, you would put your callback selector for you contract in.
    // 8 bytes of the function Identifier = CallbackTest in the SecretPath Solana Contract
    const functionIdentifier = [196, 61, 185, 224, 30, 229, 25, 52];
    const programId = program.programId.toBuffer();

    // Callback Selector is ProgramId (32 bytes) + function identifier (8 bytes) concatenated
    const callbackSelector = Buffer.concat([
      programId,
      Buffer.from(functionIdentifier),
    ]);

    const payload = {
      data,
      routing_info: routingContract,
      routing_code_hash: routingCodeHash,
      user_address: provider.publicKey.toBase58(),
      user_key: Buffer.from(new Uint8Array(4)).toString("base64"),
      callback_address: "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN",
      callback_selector: callbackSelector.toString("base64"),
      callback_gas_limit: callbackGasLimit,
    };

    const payloadJson = JSON.stringify(payload);
    const plaintext = Buffer.from(payloadJson);

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

  it("Sends a task", async () => {
    const taskDestinationNetwork = "pulsar-3";
    const routingContract = "secret15n9rw7leh9zc64uqpfxqz2ap3uz4r90e0uz3y3";
    const routingCodeHash = "931a6fa540446ca028955603fa4b924790cd3c65b3893196dc686de42b833f9c";
    const handle = "request_random";
    const callbackGasLimit = 1000000;

    const data = JSON.stringify({ numWords: 10 });
    const nonce = Buffer.from(new Uint8Array(12));

    // This is an empty callback for the sake of having a callback in the sample code.
    // Here, you would put your callback selector for you contract in.
    // 8 bytes of the function Identifier = CallbackTest in the SecretPath Solana Contract
    const functionIdentifier = [196, 61, 185, 224, 30, 229, 25, 52];
    const programId = program.programId.toBuffer();

    // Callback Selector is ProgramId (32 bytes) + function identifier (8 bytes) concatenated
    const callbackSelector = Buffer.concat([
      programId,
      Buffer.from(functionIdentifier),
    ]);

    const payload = {
      data,
      routing_info: routingContract,
      routing_code_hash: routingCodeHash,
      user_address: provider.publicKey.toBase58(),
      user_key: Buffer.from(new Uint8Array(4)).toString("base64"),
      callback_address: "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN",
      callback_selector: callbackSelector.toString("base64"),
      callback_gas_limit: callbackGasLimit,
    };

    const payloadJson = JSON.stringify(payload);
    const plaintext = Buffer.from(payloadJson);

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
