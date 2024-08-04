import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaGateway } from "../target/types/solana_gateway";
import { keccak256, getBytes } from "ethers";
import * as web3 from "@solana/web3.js";
import { clusterApiUrl, Connection } from "@solana/web3.js";

describe("solana-gateway", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.SolanaGateway as Program<SolanaGateway>;
  const provider = anchor.getProvider();
  const connection = new Connection(clusterApiUrl("devnet"), "confirmed");

  it("Is initialized!", async () => {
    // Call the initialize method on the program
    try {
      // Derive the PDA
      const [gateway_pda, gateway_bump] = web3.PublicKey.findProgramAddressSync(
        [Buffer.from("gateway_state")],
        program.programId
      );

      const [task_pda, task_bump] = web3.PublicKey.findProgramAddressSync(
        [Buffer.from("task_state")],
        program.programId
      );

      // Extract the signer from the provider

      let accountExists = true;

      try {
        // Try to fetch the gateway state
        const gatewayState = await program.account.gatewayState.fetch(gateway_pda);
        console.log("PDA is already initialized.");
      } catch (err) {
        // Handle the case where the account does not exist or has no data
        if (err.message.includes("Account does not exist or has no data")) {
          console.log("PDA not initialized yet.");
          accountExists = false;
        } else {
          throw err; // Re-throw if it's a different error
        }
      }

      // Initialize the PDA if it doesn't exist yet
      if (!accountExists) {
        console.log("Init PDA");
        const tx = await program.methods
          .initialize()
          .accounts({
            owner: provider.wallet.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([provider.wallet.payer])
          .rpc();

        console.log("Initialized Account", tx);  
        for (let i = 2; i <= 30; i++) {
            
            const tx2 = await program.methods
            .increaseTaskState(new anchor.BN(i*10240))
            .accounts({
              gatewayState: gateway_pda,
              taskStake: task_pda,
              owner: provider.wallet.publicKey,
              systemProgram: web3.SystemProgram.programId,
            })
            .instruction()
          // Sign and send the transaction, and wait for confirmation
            await anchor.web3.sendAndConfirmTransaction(
              connection,
              new anchor.web3.Transaction().add(tx2),
              [provider?.wallet.payer],
              {
                commitment: 'confirmed',
              }
            );
            console.log("Reallocated Account: ", i);
          }

          throw Error;
      }

      const task_destination_network = "pulsar-3";
      const routing_contract = "secret15n9rw7leh9zc64uqpfxqz2ap3uz4r90e0uz3y3"; //the contract you want to call in secret
      const routing_code_hash =
        "931a6fa540446ca028955603fa4b924790cd3c65b3893196dc686de42b833f9c"; //its codehash

      const numWords = 10;
      const callback_gas_limit = 1000000;

      const data = JSON.stringify({
        numWords: Number(numWords),
      });

      const callbackAddress = "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN";
      //This is an empty callback for the sake of having a callback in the sample code.
      //Here, you would put your callback selector for you contract in.
      //const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"))
      const callbackSelector = "0x00";
      const callbackGasLimit = Number(callback_gas_limit);

      //the function name of the function that is called on the private contract
      const handle = "request_random";

      //payload data that are going to be encrypted
      const payload = {
        data: data,
        routing_info: routing_contract,
        routing_code_hash: routing_code_hash,
        user_address: provider.publicKey.toBase58(),
        user_key: Buffer.from(new Uint8Array(4)).toString("base64"),
        callback_address: callbackAddress,
        callback_selector: Buffer.from(new Uint8Array(4)).toString("base64"),
        callback_gas_limit: callbackGasLimit,
      };

      //build a Json of the payload
      const payloadJson = JSON.stringify(payload);
      const plaintext = Buffer.from(payloadJson);

      //generate a nonce for ChaCha20-Poly1305 encryption
      //DO NOT skip this, stream cipher encryptions are only secure with a random nonce!
      const nonce = crypto.getRandomValues(new Uint8Array(12));

      //Encrypt the payload using ChachaPoly1305 and concat the ciphertext+tag to fit the Rust ChaChaPoly1305 requirements
      //const [ciphertextClient, tagClient] = chacha20_poly1305_seal(sharedKey, nonce, plaintext);
      //const ciphertext = concat([ciphertextClient, tagClient]);

      //get Metamask to sign the payloadhash with personal_sign
      const ciphertextHash = "test";

      //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
      const payloadHash = Buffer.from(getBytes(keccak256(plaintext)));

      const payloadBase64 = Buffer.from(payloadJson).toString("base64");

      // Convert payloadBase64 to a buffer and sign it
      const payload_buffer = Buffer.from(payloadBase64);
      const keypair = (provider.wallet as any).payer as web3.Keypair;

      // Sign the message
      // const payload_signature = web3.sign(payload_buffer, keypair.secretKey);

      const executionInfo = {
        userKey: Buffer.from(new Uint8Array(4)), // Replace with actual user key
        userPubkey: Buffer.from(new Uint8Array(4)), // Replace with actual user pubkey
        routingCodeHash: routing_code_hash,
        taskDestinationNetwork: task_destination_network,
        handle: handle,
        nonce: Buffer.from(nonce), // Replace with actual nonce
        callbackGasLimit: callback_gas_limit, // Replace with actual gas limit
        payload: plaintext, // Ensure payload is a Buffer
        payloadSignature: Buffer.from("AA="), // Replace with actual payload signature, as a Buffer
      };

      for (let i = 0; i < 600; i++) {
        const tx2 = await program.methods
          .send(provider.publicKey, routing_contract, executionInfo)
          .accounts({
            gatewayState: gateway_pda,
            taskStake: task_pda,
            user: provider.publicKey,
            systemProgram: anchor.web3.SystemProgram.programId,
          })
          .instruction()
         // Sign and send the transaction, and wait for confirmation
          const transactionSignature = await anchor.web3.sendAndConfirmTransaction(
            connection,
            new anchor.web3.Transaction().add(tx2),
            [provider?.wallet.payer],
            {
              commitment: 'confirmed',
            }
          );
          console.log("Text Send TX number: ", i);
      }

      console.log("Gateway send");
    } catch (err) {
      console.error("Error initializing gateway state:", err);
    }
  });
});
