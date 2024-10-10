import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaGateway } from "../target/types/solana_gateway";
import { getBytes, keccak256 } from "ethers";
import * as web3 from "@solana/web3.js";
import { clusterApiUrl, Connection } from "@solana/web3.js";
import crypto from "crypto";
import * as assert from "assert";
import { bs58 } from "@coral-xyz/anchor/dist/cjs/utils/bytes";

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

  it("Increases task state size if necessary", async () => {
    // Determine the maximum size needed
    const maxSize = 30 * 10240;

    // Fetch the current task state account data
    const taskStateAccount = await program.provider.connection.getAccountInfo(
      taskPDA
    );
    const currentSize = taskStateAccount.data.length; // Assuming 'data' contains the state information
    // Only proceed if the max size is larger than the current size
    if (maxSize > currentSize) {
      for (let i = 2; i <= 30; i++) {
        const newSize = i * 10240;

        const tx = await program.methods
          .increaseTaskState(new anchor.BN(newSize))
          .accounts({
            gatewayState: gatewayPDA,
            taskState: taskPDA,
            owner: provider.wallet.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .rpc();

        console.log("Reallocated Task State with size:", newSize);
      }
    } else {
      console.log(
        "No reallocation needed, current size is already sufficient:",
        currentSize
      );
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
    const updatedGatewayState = await program.account.gatewayState.fetch(
      gatewayPDA
    );
    const updatedTaskId = updatedGatewayState.taskId.toNumber();

    // Check that the taskId has been updated correctly
    assert.strictEqual(
      updatedTaskId,
      newTaskId,
      `Expected taskId to be ${newTaskId}, but found ${updatedTaskId}`
    );
  });

  it("Prints tasks from task_state", async () => {
    // Fetch the raw data of the task_state account
    const accountInfo = await provider.connection.getAccountInfo(taskPDA);
    if (!accountInfo) {
      console.log("Task State account does not exist");
      return;
    }
    const data = accountInfo.data;

    const TASK_SIZE = 41;
    const PAYLOAD_HASH_SIZE = 32;
    const TASK_ID_SIZE = 8;
    const COMPLETED_OFFSET = 40; // Last byte for completed flag

    // Calculate the number of tasks based on a known constant or from data length
    //const numTasks = Math.floor(data.length / TASK_SIZE);
    const numTasks = 20;
    console.log(`Number of tasks: ${numTasks}`);

    for (let i = 0; i < numTasks; i++) {
      const start = i * TASK_SIZE;
      const taskBuffer = data.slice(start, start + TASK_SIZE);

      // Extract payload_hash (32 bytes)
      const payloadHash = taskBuffer
        .slice(0, PAYLOAD_HASH_SIZE)
        .toString("hex");

      // Extract task_id (8 bytes), little-endian
      const taskIdBuffer = taskBuffer.slice(
        PAYLOAD_HASH_SIZE,
        PAYLOAD_HASH_SIZE + TASK_ID_SIZE
      );
      const taskId = Buffer.from(taskIdBuffer).readBigUInt64LE();

      // Extract completed (1 byte)
      const completed = taskBuffer[COMPLETED_OFFSET] !== 0;

      console.log(`Task ID: ${taskId}`);
      console.log(`  Payload Hash: 0x${payloadHash}`);
      console.log(`  Completed: ${completed}`);
      console.log(`  Output: ${taskBuffer.toString("hex")}`);
    }
  });

  it("Performs task payout", async () => {
    // Fetch initial balances
    const ownerInitialBalance = await connection.getBalance(
      provider.wallet.publicKey
    );
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
    const txSig = await provider.sendAndConfirm(
      new web3.Transaction().add(transferIx),
      undefined,
      { commitment: "confirmed" }
    );
    console.log("Transferred lamports to gatewayState:", txSig);

    // Fetch balances after funding
    const ownerAfterFundingBalance = await connection.getBalance(
      provider.wallet.publicKey
    );
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
      .rpc({ commitment: "confirmed" });

    console.log("Payout completed:", payoutTx);

    // Fetch balances after payout
    const ownerFinalBalance = await connection.getBalance(
      provider.wallet.publicKey
    );
    const gatewayFinalBalance = await connection.getBalance(gatewayPDA);

    console.log("Owner final balance:", ownerFinalBalance);
    console.log("Gateway final balance:", gatewayFinalBalance);

    // Verify that owner's balance increased (minus transaction fees)
    assert.ok(
      ownerFinalBalance > ownerAfterFundingBalance, // accounting for fees
      "Owner's balance did not increase"
    );

    // Verify that gateway's balance decreased appropriately
    const rentExemptMinimum =
      await connection.getMinimumBalanceForRentExemption(
        (
          await connection.getAccountInfo(gatewayPDA)
        ).data.length
      );
    assert.ok(
      gatewayFinalBalance <= rentExemptMinimum,
      "Gateway's balance did not decrease to rent-exempt minimum"
    );
  });

  it("Sends a task and verifies the LogNewTask event", async () => {
    const taskDestinationNetwork = "pulsar-3";
    const routingContract = "secret1cknezaxnzfys2w8lyyrr7fed9wxejvgq7alhqx";
    const routingCodeHash =
      "0b9395a7550b49d2b8ed73497fd2ebaf896c48950c4186e491ded6d22e58b8c3";
    const handle = "request_random";
    const callbackGasLimit = 1000000;

    const data = JSON.stringify({ numWords: 10 });

    // Empty nonce because there is no encryption.
    const nonce = crypto.randomBytes(12);

    // Function Identifier for CallbackTest in the SecretPath Solana Contract
    const functionIdentifier = Buffer.from([
      196, 61, 185, 224, 30, 229, 25, 52,
    ]);

    const programId = program.programId.toBuffer();

    // Callback Selector is ProgramId (32 bytes) + function identifier (8 bytes)
    const callbackSelector = Buffer.concat([programId, functionIdentifier]);

    // Include some address as a test
    const testAddress1 = new web3.PublicKey(
      "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN"
    );
    const testAddress2 = new web3.PublicKey(
      "GPuidhXoR6PQ5skXEdrnJehYbffCXfLDf7pcnxH2EW7P"
    );
    const callbackAddress = Buffer.concat([
      testAddress1.toBuffer(),
      testAddress2.toBuffer(),
    ]).toString("base64");

    const payload = {
      data,
      routing_info: routingContract,
      routing_code_hash: routingCodeHash,
      user_address: provider.publicKey.toBase58(),
      user_key: Buffer.from(new Uint8Array(2)).toString("base64"),
      callback_address: callbackAddress,
      callback_selector: callbackSelector.toString("base64"),
      callback_gas_limit: callbackGasLimit,
    };

    const payloadJson = JSON.stringify(payload);
    const plaintext = Buffer.from(payloadJson);

    // Empty payload signature (64 bytes of zeros)
    const emptySignature = new Uint8Array(64).fill(0);

    const executionInfo = {
      userKey: Buffer.from(new Uint8Array(2)),
      userPubkey: Buffer.from(new Uint8Array(2)),
      routingCodeHash,
      taskDestinationNetwork,
      handle,
      nonce: Array.from(nonce),
      callbackGasLimit,
      payload: plaintext,
      payloadSignature: Array.from(emptySignature),
    };

    // Send the transaction
    const txSignature = await program.methods
      .send(provider.publicKey, routingContract, executionInfo)
      .accounts({
        gatewayState: gatewayPDA,
        taskState: taskPDA,
        user: provider.publicKey,
        systemProgram: web3.SystemProgram.programId,
      } as any)
      .rpc({ commitment: "confirmed" });

    console.log("Task sent:", txSignature);

    // Wait for transaction confirmation
    const latestBlockhash = await provider.connection.getLatestBlockhash();
    const confirmation = await provider.connection.confirmTransaction({
      signature: txSignature,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    });

    // Ensure the transaction was successful
    assert.strictEqual(
      confirmation.value.err,
      null,
      "Transaction failed: " + JSON.stringify(confirmation.value.err)
    );

    // Fetch the transaction details
    const txDetails = await provider.connection.getTransaction(txSignature, {
      commitment: "confirmed",
    });
    assert.ok(txDetails, "Transaction details not found");

    // Extract logs from transaction meta
    const logs = txDetails.meta.logMessages;
    assert.ok(logs, "No logs found in transaction");

    console.log(logs);
    // Find the LogNewTask event in the logs
    let logNewTaskBase64 = null;
    for (const log of logs) {
      if (log.startsWith("Program log: LogNewTask:")) {
        console.log(log);
        // Extract the base64-encoded data after the prefix
        logNewTaskBase64 = log.split("Program log: LogNewTask:")[1].trim();
        break;
      }
    }

    assert.ok(logNewTaskBase64, "LogNewTask event not found in logs");

    // Decode the base64-encoded data
    const logNewTaskDataBuffer = Buffer.from(logNewTaskBase64, "base64");

    // Define the Borsh schema
    const borsh = require("borsh");

    class LogNewTask {
      constructor(props) {
        Object.assign(this, props);
      }
    }

    // Borsh schema for deserialization
    const logNewTaskSchema = new Map([
      [
        LogNewTask,
        {
          kind: "struct",
          fields: [
            ["task_id", "u64"],
            ["source_network", "string"],
            ["user_address", ["u8"]],
            ["routing_info", "string"],
            ["payload_hash", [32]],
            ["user_key", ["u8"]],
            ["user_pubkey", ["u8"]],
            ["routing_code_hash", "string"],
            ["task_destination_network", "string"],
            ["handle", "string"],
            ["nonce", [12]],
            ["callback_gas_limit", "u32"],
            ["payload", ["u8"]],
            ["payload_signature", [64]],
          ],
        },
      ],
    ]);

    // Deserialize the data using Borsh
    const logNewTaskData = borsh.deserialize(
      logNewTaskSchema,
      LogNewTask,
      logNewTaskDataBuffer
    );

    // Now, add assertions to verify the contents of logNewTaskData

    // Assert source_network
    assert.strictEqual(
      logNewTaskData.source_network,
      "SolDN",
      "Source network does not match"
    );

    // Assert task_destination_network
    assert.strictEqual(
      logNewTaskData.task_destination_network,
      taskDestinationNetwork,
      "Task destination network does not match"
    );

    // Assert payload_hash
    const expectedPayloadHash = Buffer.from(getBytes(keccak256(plaintext)));

    const payloadHashFromLog = Buffer.from(logNewTaskData.payload_hash);

    assert.deepStrictEqual(
      payloadHashFromLog,
      expectedPayloadHash,
      `Payload hash does not match. Expected: ${payloadHashFromLog}, Got: ${expectedPayloadHash}`
    );

    // Assert user_address
    const userAddressBytes = bs58.decode(provider.publicKey.toBase58());
    const userAddressFromLog = Buffer.from(logNewTaskData.user_address);

    assert.deepStrictEqual(
      userAddressFromLog,
      userAddressBytes,
      "User address does not match"
    );

    // Assert routing_info
    assert.strictEqual(
      logNewTaskData.routing_info,
      routingContract,
      "Routing info does not match"
    );

    // Assert routing_code_hash
    assert.strictEqual(
      logNewTaskData.routing_code_hash,
      routingCodeHash,
      "Routing code hash does not match"
    );

    // Assert handle
    assert.strictEqual(logNewTaskData.handle, handle, "Handle does not match");

    // Assert nonce
    assert.deepStrictEqual(
      Array.from(logNewTaskData.nonce),
      Array.from(nonce),
      `Nonce does not match. Expected: ${logNewTaskData.nonce}, Got: ${nonce}`
    );

    // Assert callback_gas_limit
    assert.strictEqual(
      logNewTaskData.callback_gas_limit,
      callbackGasLimit,
      "Callback gas limit does not match"
    );

    // Assert payload
    const payloadFromLog = Buffer.from(logNewTaskData.payload);

    assert.deepStrictEqual(payloadFromLog, plaintext, "Payload does not match");

    // Assert user_key
    const userKeyFromLog = Buffer.from(logNewTaskData.user_key);

    assert.deepStrictEqual(
      userKeyFromLog,
      Buffer.from(new Uint8Array(2)),
      "User key does not match"
    );

    // Assert user_pubkey
    const userPubkeyFromLog = Buffer.from(logNewTaskData.user_pubkey);

    assert.deepStrictEqual(
      userPubkeyFromLog,
      Buffer.from(new Uint8Array(2)),
      "User pubkey does not match"
    );

    // Assert payload_signature
    const payloadSignatureFromLog = Buffer.from(
      logNewTaskData.payload_signature
    );

    assert.deepStrictEqual(
      Buffer.from(payloadSignatureFromLog),
      Buffer.from(emptySignature),
      "Payload signature does not match"
    );

    // Fetch and output the task state initially
    const initialTaskState = await getTaskState(logNewTaskData.task_id);
    if (initialTaskState) {
      console.log(`Initial Task State:`);
      console.log(`  Task ID: ${initialTaskState.taskId}`);
      console.log(
        `  Payload Hash: 0x${initialTaskState.payloadHash.toString("hex")}`
      );
      console.log(`  Completed: ${initialTaskState.completed}`);
    }

    // Perform the deep checks (assertions) outside the function
    if (initialTaskState) {
      assert.deepStrictEqual(
        Buffer.from(logNewTaskData.payload_hash),
        Buffer.from(initialTaskState.payloadHash),
        `Stored payloadHash do not match. Expected: ${Buffer.from(
          logNewTaskData.payload_hash
        ).toString("hex")}, Got: ${initialTaskState.payloadHash.toString(
          "hex"
        )}`
      );

      assert.deepStrictEqual(
        Number(logNewTaskData.task_id),
        Number(initialTaskState.taskId),
        `Stored Task_ids do not match. Expected: ${logNewTaskData.task_id}, Got: ${initialTaskState.taskId}`
      );
      assert.deepStrictEqual(
        initialTaskState.completed,
        false,
        `Task must not be completed at this point.`
      );
    }

    // Sleep for 20 seconds
    await new Promise((resolve) => setTimeout(resolve, 20000));

    // Fetch and output the task state after the delay
    const updatedTaskState = await getTaskState(logNewTaskData.task_id);
    if (updatedTaskState) {
      console.log(`Updated Task State after 15 seconds:`);
      console.log(`  Task ID: ${updatedTaskState.taskId}`);
      console.log(
        `  Payload Hash: 0x${updatedTaskState.payloadHash.toString("hex")}`
      );
      console.log(`  Completed: ${updatedTaskState.completed}`);
    }

    // Perform the deep checks again if necessary
    if (updatedTaskState) {
      assert.deepStrictEqual(
        Buffer.from(logNewTaskData.payload_hash),
        Buffer.from(updatedTaskState.payloadHash),
        `Stored payloadHash do not match after delay. Expected: ${Buffer.from(
          logNewTaskData.payload_hash
        ).toString("hex")}, Got: ${updatedTaskState.payloadHash.toString(
          "hex"
        )}`
      );

      assert.deepStrictEqual(
        Number(logNewTaskData.task_id),
        Number(updatedTaskState.taskId),
        `Stored Task_ids do not match after delay. Expected: ${logNewTaskData.task_id}, Got: ${updatedTaskState.taskId}`
      );
      assert.deepStrictEqual(
        updatedTaskState.completed,
        true,
        `Task must be completed after execution.`
      );
    }
  });

  async function getTaskState(task_id: number) {
    // Fetch the raw data of the task_state account
    const accountInfo = await provider.connection.getAccountInfo(taskPDA);
    if (!accountInfo) {
      console.log("Task State account does not exist");
      return null;
    }

    const TASK_SIZE = 41;
    const PAYLOAD_HASH_SIZE = 32;
    const TASK_ID_SIZE = 8;
    const COMPLETED_OFFSET = 40; // Last byte for completed flag

    // +8 bytes for the account discriminator.
    const start = task_id * TASK_SIZE + 8;
    const taskBuffer = accountInfo.data.slice(start, start + TASK_SIZE);

    // Extract payload_hash (32 bytes)
    const payloadHash = taskBuffer.slice(0, PAYLOAD_HASH_SIZE);

    // Extract task_id (8 bytes), little-endian
    const taskIdBuffer = taskBuffer.slice(
      PAYLOAD_HASH_SIZE,
      PAYLOAD_HASH_SIZE + TASK_ID_SIZE
    );
    const taskId = Buffer.from(taskIdBuffer).readBigUInt64LE();

    // Extract completed (1 byte)
    const completed = taskBuffer[COMPLETED_OFFSET] !== 0;

    // Return the extracted variables
    return { taskId, payloadHash, completed };
  }

  it("Sends a randomness request and verifies the LogNewTask event", async () => {
    const numWords = 10;
    const callbackComputeLimit = 1000000;
    const vrfContractAddress = "secret1cknezaxnzfys2w8lyyrr7fed9wxejvgq7alhqx";
    const vrfCodeHash =
      "0b9395a7550b49d2b8ed73497fd2ebaf896c48950c4186e491ded6d22e58b8c3";
    const taskDestinationNetwork = "pulsar-3";
    const chainId = "SolDN";
    const handle = "request_random";
  
    // Callback Program ID (32 bytes) and Function Discriminator (8 bytes)
    const callbackProgramId = program.programId.toBuffer(); // 32 bytes
    const callbackFunctionDiscriminator = [
      196, 61, 185, 224, 30, 229, 25, 52,
    ]; // 8 bytes
  
    // Concatenate Callback Selector (Program ID + Function Discriminator)
    const callbackSelector = Buffer.concat([
      callbackProgramId,
      Buffer.from(callbackFunctionDiscriminator),
    ]); // 40 bytes
    const callbackSelectorEncoded = callbackSelector.toString("base64");
  
    // Test Addresses for Callback Accounts
    const testAddress1 = new web3.PublicKey(
      "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN"
    );
    const testAddress2 = new web3.PublicKey(
      "GPuidhXoR6PQ5skXEdrnJehYbffCXfLDf7pcnxH2EW7P"
    );
  
    // Concatenate Callback Accounts (must be a multiple of 32 bytes)
    const callbackAccounts = Buffer.concat([
      testAddress1.toBuffer(),
      testAddress2.toBuffer(),
    ]);
    const callbackAccountsEncoded = callbackAccounts.toString("base64");
  
    // Prepare the payload as per the Rust function
    const payload = {
      data: `{"numWords":${numWords}}`,
      routing_info: vrfContractAddress,
      routing_code_hash: vrfCodeHash,
      user_address: "AAA=",
      user_key: "AAA=",
      callback_address: callbackAccountsEncoded,
      callback_selector: callbackSelectorEncoded,
      callback_gas_limit: callbackComputeLimit,
    };
  
    const payloadJson = JSON.stringify(payload);
    const plaintext = Buffer.from(payloadJson);
  
    // Compute the expected payload hash
    const expectedPayloadHash = Buffer.from(getBytes(keccak256(plaintext)));
  
    // Empty payload signature (64 bytes of zeros)
    const emptySignature = new Uint8Array(64).fill(0);
  
   // Send the transaction
    const txSignature = await program.methods
      .requestRandomness(
        numWords,
        callbackComputeLimit,
        Array.from(callbackProgramId),
        Array.from(callbackFunctionDiscriminator),
        callbackAccounts
      )
      .accounts({
        gatewayState: gatewayPDA,
        taskState: taskPDA,
        user: provider.publicKey,
        systemProgram: web3.SystemProgram.programId,
      } as any)
      .rpc({ commitment: "confirmed" });
  
    console.log("Task sent:", txSignature);
  
    // Wait for transaction confirmation
    const latestBlockhash = await provider.connection.getLatestBlockhash();
    const confirmation = await provider.connection.confirmTransaction({
      signature: txSignature,
      blockhash: latestBlockhash.blockhash,
      lastValidBlockHeight: latestBlockhash.lastValidBlockHeight,
    });
  
    // Ensure the transaction was successful
    assert.strictEqual(
      confirmation.value.err,
      null,
      "Transaction failed: " + JSON.stringify(confirmation.value.err)
    );
  
    // Fetch the transaction details
    const txDetails = await provider.connection.getTransaction(txSignature, {
      commitment: "confirmed",
    });
    assert.ok(txDetails, "Transaction details not found");
  
    // Extract logs from transaction meta
    const logs = txDetails.meta.logMessages;
    assert.ok(logs, "No logs found in transaction");
  
    console.log(logs);
    // Find the LogNewTask event in the logs
    let logNewTaskBase64 = null;
    for (const log of logs) {
      if (log.startsWith("Program log: LogNewTask:")) {
        console.log(log);
        // Extract the base64-encoded data after the prefix
        logNewTaskBase64 = log.split("Program log: LogNewTask:")[1].trim();
        break;
      }
    } 
  
   assert.ok(logNewTaskBase64, "LogNewTask event not found in logs");
  
    // Decode the base64-encoded data
    const logNewTaskDataBuffer = Buffer.from(logNewTaskBase64, "base64");
  
    // Define the Borsh schema
    const borsh = require("borsh");
  
    class LogNewTask {
      constructor(props) {
        Object.assign(this, props);
      }
    }
  
    // Borsh schema for deserialization
    const logNewTaskSchema = new Map([
      [
        LogNewTask,
        {
          kind: "struct",
          fields: [
            ["task_id", "u64"],
            ["source_network", "string"],
            ["user_address", ["u8"]],
            ["routing_info", "string"],
            ["payload_hash", [32]],
            ["user_key", ["u8"]],
            ["user_pubkey", ["u8"]],
            ["routing_code_hash", "string"],
            ["task_destination_network", "string"],
            ["handle", "string"],
            ["nonce", [12]],
            ["callback_gas_limit", "u32"],
            ["payload", ["u8"]],
            ["payload_signature", [64]],
          ],
        },
      ],
    ]);
  
    // Deserialize the data using Borsh
    const logNewTaskData = borsh.deserialize(
      logNewTaskSchema,
      LogNewTask,
      logNewTaskDataBuffer
    );
  
    // Now, add assertions to verify the contents of logNewTaskData
  
    // Assert source_network
    assert.strictEqual(
      logNewTaskData.source_network,
      chainId,
      "Source network does not match"
    );
  
    // Assert task_destination_network
    assert.strictEqual(
      logNewTaskData.task_destination_network,
      taskDestinationNetwork,
      "Task destination network does not match"
    );
  
    // Assert payload_hash
    const payloadHashFromLog = Buffer.from(logNewTaskData.payload_hash);
  
    assert.deepStrictEqual(
      payloadHashFromLog,
      expectedPayloadHash,
      `Payload hash does not match. Expected: ${expectedPayloadHash.toString(
        "hex"
      )}, Got: ${payloadHashFromLog.toString("hex")}`
    );
  
    // Assert user_address (expecting 4 zero bytes)
    const expectedUserAddress = Buffer.from(new Uint8Array(2));
    const userAddressFromLog = Buffer.from(logNewTaskData.user_address);
  
    assert.deepStrictEqual(
      userAddressFromLog,
      expectedUserAddress,
      "User address does not match"
    );
  
    // Assert routing_info
    assert.strictEqual(
      logNewTaskData.routing_info,
      vrfContractAddress,
      "Routing info does not match"
    );
  
    // Assert routing_code_hash
    assert.strictEqual(
      logNewTaskData.routing_code_hash,
      vrfCodeHash,
      "Routing code hash does not match"
    );
  
    // Assert handle
    assert.strictEqual(logNewTaskData.handle, handle, "Handle does not match");
  
    // Assert nonce (expecting 12 zero bytes)
    const expectedNonce = Buffer.from(new Uint8Array(12));
    const nonceFromLog = Buffer.from(logNewTaskData.nonce);
  
    assert.deepStrictEqual(
      nonceFromLog,
      expectedNonce,
      `Nonce does not match. Expected: ${expectedNonce.toString(
        "hex"
      )}, Got: ${nonceFromLog.toString("hex")}`
    );
  
    // Assert callback_gas_limit
    assert.strictEqual(
      logNewTaskData.callback_gas_limit,
      callbackComputeLimit,
      "Callback gas limit does not match"
    );
  
    // Assert payload
    const payloadFromLog = Buffer.from(logNewTaskData.payload);
  
    assert.deepStrictEqual(payloadFromLog, plaintext, "Payload does not match");
  
    // Assert user_key (expecting 4 zero bytes)
    const expectedUserKey = Buffer.from(new Uint8Array(2));
    const userKeyFromLog = Buffer.from(logNewTaskData.user_key);
  
    assert.deepStrictEqual(
      userKeyFromLog,
      expectedUserKey,
      "User key does not match"
    );
  
    // Assert user_pubkey (expecting 4 zero bytes)
    const expectedUserPubkey = Buffer.from(new Uint8Array(2));
    const userPubkeyFromLog = Buffer.from(logNewTaskData.user_pubkey);
  
    assert.deepStrictEqual(
      userPubkeyFromLog,
      expectedUserPubkey,
      "User pubkey does not match"
    );
  
    // Assert payload_signature (expecting 64 zero bytes)
    const payloadSignatureFromLog = Buffer.from(
      logNewTaskData.payload_signature
    );
  
    assert.deepStrictEqual(
      payloadSignatureFromLog,
      Buffer.from(emptySignature),
      "Payload signature does not match"
    );
  
    // Fetch and output the task state initially
    const initialTaskState = await getTaskState(logNewTaskData.task_id);
    if (initialTaskState) {
      console.log(`Initial Task State:`);
      console.log(`  Task ID: ${initialTaskState.taskId}`);
      console.log(
        `  Payload Hash: 0x${initialTaskState.payloadHash.toString("hex")}`
      );
      console.log(`  Completed: ${initialTaskState.completed}`);
    }
  
    // Perform the deep checks (assertions) outside the function
    if (initialTaskState) {
      assert.deepStrictEqual(
        Buffer.from(logNewTaskData.payload_hash),
        Buffer.from(initialTaskState.payloadHash),
        `Stored payloadHash do not match. Expected: ${Buffer.from(
          logNewTaskData.payload_hash
        ).toString("hex")}, Got: ${initialTaskState.payloadHash.toString("hex")}`
      );
  
      assert.deepStrictEqual(
        Number(logNewTaskData.task_id),
        Number(initialTaskState.taskId),
        `Stored Task_ids do not match. Expected: ${logNewTaskData.task_id}, Got: ${initialTaskState.taskId}`
      );
      assert.deepStrictEqual(
        initialTaskState.completed,
        false,
        `Task must not be completed at this point.`
      );
    }
  
    // Sleep for 20 seconds
    await new Promise((resolve) => setTimeout(resolve, 20000));
  
    // Fetch and output the task state after the delay
    const updatedTaskState = await getTaskState(logNewTaskData.task_id);
    if (updatedTaskState) {
      console.log(`Updated Task State after 15 seconds:`);
      console.log(`  Task ID: ${updatedTaskState.taskId}`);
      console.log(
        `  Payload Hash: 0x${updatedTaskState.payloadHash.toString("hex")}`
      );
      console.log(`  Completed: ${updatedTaskState.completed}`);
    }
  
    // Perform the deep checks again if necessary
    if (updatedTaskState) {
      assert.deepStrictEqual(
        Buffer.from(logNewTaskData.payload_hash),
        Buffer.from(updatedTaskState.payloadHash),
        `Stored payloadHash do not match after delay. Expected: ${Buffer.from(
          logNewTaskData.payload_hash
        ).toString("hex")}, Got: ${updatedTaskState.payloadHash.toString("hex")}`
      );
  
      assert.deepStrictEqual(
        Number(logNewTaskData.task_id),
        Number(updatedTaskState.taskId),
        `Stored Task_ids do not match after delay. Expected: ${logNewTaskData.task_id}, Got: ${updatedTaskState.taskId}`
      );
      assert.deepStrictEqual(
        updatedTaskState.completed,
        true,
        `Task must be completed after execution.`
      );
    } 
  });
  

  /*it("Performs post execution", async () => {
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
  });*/
});
