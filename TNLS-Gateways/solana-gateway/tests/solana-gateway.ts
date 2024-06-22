import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { SolanaGateway } from "../target/types/solana_gateway";
import { keccak256, getBytes } from 'ethers';
import * as web3 from "@solana/web3.js";

describe("solana-gateway", () => {
  // Configure the client to use the local cluster.
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace.SolanaGateway as Program<SolanaGateway>;
  const provider = anchor.getProvider();


  it("Is initialized!", async () => {
    // Generate a new keypair for the gateway state account
    const gatewayState = anchor.web3.Keypair.generate();

    // Determine the rent-exempt balance for the new account
    const lamports = await provider.connection.getMinimumBalanceForRentExemption(
      8 + 8 + 8 + 9000
    );


    // Call the initialize method on the program
    try {
      //@ts-ignore
      const tx = await program.methods
        .initialize()
        .accounts({
          gatewayState: gatewayState.publicKey,
          owner: provider.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([gatewayState])
        .rpc();

        console.log("Your transaction signature", tx);
        console.log("Gateway state initialized:", gatewayState.publicKey.toString());
      
      const task_destination_network = "pulsar-3"
      const routing_contract = "secret1fxs74g8tltrngq3utldtxu9yys5tje8dzdvghr" //the contract you want to call in secret
      const routing_code_hash = "49ffed0df451622ac1865710380c14d4af98dca2d32342bb20f2b22faca3d00d" //its codehash
  
      const numWords = 10;
        const callback_gas_limit = "10000";
        
        const data = JSON.stringify({
            numWords: Number(numWords)
        })

        const callbackAddress = "HZy2bXo1NmcTWURJvk9c8zofqE2MUvpu7wU722o7gtEN";
        //This is an empty callback for the sake of having a callback in the sample code.
        //Here, you would put your callback selector for you contract in. 
       //const callbackSelector = iface.getSighash(iface.getFunction("upgradeHandler"))
       const callbackSelector = "0x00"
        const callbackGasLimit = Number(callback_gas_limit)

        //the function name of the function that is called on the private contract
        const handle = "request_random"

        //payload data that are going to be encrypted
        const payload = {
            data: data,
            routing_info: routing_contract,
            routing_code_hash: routing_code_hash,
            user_address: provider.publicKey.toString(),
            user_key: "AA==",
            callback_address: "AA==",
            callback_selector: "AA==",
            callback_gas_limit: callbackGasLimit,
        }

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
        const ciphertextHash = "test"

        //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
        const payloadHash = Buffer.from(getBytes(keccak256(plaintext)));
        
        const payloadBase64 = Buffer.from(payloadJson).toString('base64');
        console.log(payloadBase64);
  
        // Convert payloadBase64 to a buffer and sign it
        const payload_buffer = Buffer.from(payloadBase64);
        const keypair = (provider.wallet as any).payer as web3.Keypair;

        // Sign the message
       // const payload_signature = web3.sign(payload_buffer, keypair.secretKey);

        const executionInfo = {
          userKey: Buffer.from(new Uint8Array(32)), // Replace with actual user key
          userPubkey: Buffer.from(new Uint8Array(32)), // Replace with actual user pubkey
          routingCodeHash: routing_code_hash,
          taskDestinationNetwork: task_destination_network,
          handle: handle,
          nonce: Buffer.from(nonce), // Replace with actual nonce
          callbackGasLimit: 2000000, // Replace with actual gas limit
          payload: plaintext, // Ensure payload is a Buffer
          payloadSignature: Buffer.from("AA="), // Replace with actual payload signature, as a Buffer
      };
      
        const tx2 = await program.methods.send(
          payloadHash,
          provider.publicKey,
          routing_contract,
          executionInfo,
        )
        .accounts({
          gatewayState: gatewayState.publicKey,
          user: provider.publicKey,
          systemProgram: anchor.web3.SystemProgram.programId,
        })
        .signers([provider?.wallet.payer])
        .rpc();

      console.log("Your transaction signature", tx2);
      console.log("Gateway send");
    } catch (err) {
      console.error("Error initializing gateway state:", err);
    }
  });
});

