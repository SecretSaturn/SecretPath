import axios from "axios";
import { Wallet, SecretNetworkClient, fromUtf8 } from "secretjs";
import fs from "fs";
import assert from "assert";
import { Payload, Contract, Sender, Binary } from "../../../TNLS-Gateways/secret/tests/GatewayContract";
import { ecdsaSign } from "secp256k1";
import { Wallet as EthWallet } from "ethers";
import { arrayify, SigningKey } from "ethers/lib/utils";
import { createHash, randomBytes } from 'crypto';
import { encrypt_payload } from '../../../TNLS-Gateways/secret/tests/encrypt-payload/pkg'
import 'dotenv/config'

var mnemonic: string;
var endpoint: string = "http://localhost:9091";
var chainId: string = "secretdev-1";

// uncomment if using .env file
// mnemonic = process.env.MNEMONIC!;
// endpoint = process.env.GRPC_WEB_URL!;
// chainId = process.env.CHAIN_ID!;

var gasTotal: number = 0;
const BROADCAST_MS = 6000; // 6000 default, 100 if using speedy block times

// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  let wallet: Wallet;
  if (mnemonic) {
    wallet = new Wallet(mnemonic);
  } else {
    wallet = new Wallet();
  }
  const accAddress = wallet.address;
  const client = await SecretNetworkClient.create({
    // Create a client to interact with the network
    grpcWebUrl: endpoint,
    chainId: chainId,
    wallet: wallet,
    walletAddress: accAddress,
  });

  console.log(`\nInitialized client with wallet address: ${accAddress}`);
  return client;
};

const initializeGateway = async (
  client: SecretNetworkClient,
  contractPath: string,
  scrtRngHash: string,
  scrtRngAddress: string,
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("Uploading gateway contract...");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (uploadReceipt.code !== 0) {
    console.log(
      `Failed to get code id: ${JSON.stringify(uploadReceipt.rawLog)}`
    );
    throw new Error(`Failed to upload contract`);
  }

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  gasTotal += uploadReceipt.gasUsed;
  console.log(`Upload used \x1b[33m${uploadReceipt.gasUsed}\x1b[0m gas\n`);

  const codeId = Number(codeIdKv!.value);
  console.log("Contract codeId: ", codeId);

  const contractCodeHash = await client.query.compute.codeHash(codeId);
  console.log(`Contract hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      codeId,
      initMsg: { 
        entropy: "secret",
        rng_hash: scrtRngHash,
        rng_addr: scrtRngAddress,
      },
      codeHash: contractCodeHash,
      label: "My contract" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  }

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  const encryption_pubkey = contract.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "encryption_pubkey"
  )!.value;

  const signing_pubkey = contract.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === "signing_pubkey"
  )!.value;

  console.log(`Contract address: ${contractAddress}\n`);

  // console.log(`\x1b[32mEncryption key: ${encryption_pubkey}\x1b[0m`);
  // console.log(`\x1b[32mVerification key: ${signing_pubkey}\x1b[0m\n`);

  gasTotal += contract.gasUsed;
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  var gatewayInfo: [string, string, string] = [contractCodeHash, contractAddress, encryption_pubkey];
  return gatewayInfo;
};

const initializeScrtRng = async (
  client: SecretNetworkClient,
  contractPath: string,
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("Uploading scrt-rng contract...");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (uploadReceipt.code !== 0) {
    console.log(
      `Failed to get code id: ${JSON.stringify(uploadReceipt.rawLog)}`
    );
    throw new Error(`Failed to upload contract`);
  }

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  gasTotal += uploadReceipt.gasUsed;
  console.log(`Upload used \x1b[33m${uploadReceipt.gasUsed}\x1b[0m gas\n`);

  const codeId = Number(codeIdKv!.value);
  console.log("Contract codeId: ", codeId);

  const contractCodeHash = await client.query.compute.codeHash(codeId);
  console.log(`Contract hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      codeId,
      initMsg: { initseed: "secret", prng_seed: "secret" },
      codeHash: contractCodeHash,
      label: "My contract" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  }

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  console.log(`Contract address: ${contractAddress}\n`);

  gasTotal += contract.gasUsed;
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  var scrtRngInfo: [string, string] = [contractCodeHash, contractAddress];
  return scrtRngInfo;
};

const initializeContract = async (
  client: SecretNetworkClient,
  contractPath: string,
  gatewayHash: string,
  gatewayAddress: string,
  gatewayKey: string,
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("Uploading destination contract...");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (uploadReceipt.code !== 0) {
    console.log(
      `Failed to get code id: ${JSON.stringify(uploadReceipt.rawLog)}`
    );
    throw new Error(`Failed to upload contract`);
  }

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  gasTotal += uploadReceipt.gasUsed;
  console.log(`Upload used \x1b[33m${uploadReceipt.gasUsed}\x1b[0m gas\n`);

  const codeId = Number(codeIdKv!.value);
  console.log("Contract codeId: ", codeId);

  const contractCodeHash = await client.query.compute.codeHash(codeId);
  console.log(`Contract hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      codeId,
      initMsg: {
        gateway_hash: gatewayHash,
        gateway_address: gatewayAddress,
        gateway_key: gatewayKey,
      },
      codeHash: contractCodeHash,
      label: "My contract" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  }

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  console.log(`Contract address: ${contractAddress}\n`);

  gasTotal += contract.gasUsed;
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  var gatewayInfo: [string, string] = [contractCodeHash, contractAddress];
  return gatewayInfo;
};

const getFromFaucet = async (address: string) => {
  await axios.get(`http://localhost:5000/faucet?address=${address}`);
};

async function getScrtBalance(userCli: SecretNetworkClient): Promise<string> {
  let balanceResponse = await userCli.query.bank.balance({
    address: userCli.address,
    denom: "uscrt",
  });
  return balanceResponse.balance!.amount;
}

async function fillUpFromFaucet(
  client: SecretNetworkClient,
  targetBalance: Number
) {
  let balance = await getScrtBalance(client);
  while (Number(balance) < targetBalance) {
    try {
      await getFromFaucet(client.address);
    } catch (e) {
      console.error(`\x1b[2mfailed to get tokens from faucet: ${e}\x1b[0m`);
    }
    balance = await getScrtBalance(client);
  }
  console.error(`got tokens from faucet: ${balance}\n`);
}

// Initialization procedure
async function initializeAndUploadContract() {

  const client = await initializeClient(endpoint, chainId);

  if (chainId == "secretdev-1") {await fillUpFromFaucet(client, 100_000_000)};
  
  const [scrtRngHash, scrtRngAddress] = await initializeScrtRng(
    client,
    "../../TNLS-Gateways/secret/tests/scrt-rng/contract.wasm.gz",
  );
  
  const [gatewayHash, gatewayAddress] = await initializeGateway(
    client,
    "../../TNLS-Gateways/secret/contract.wasm.gz",
    scrtRngHash,
    scrtRngAddress,
  );

  await generateKeys(client, gatewayHash, gatewayAddress, scrtRngHash, scrtRngAddress);
  const gatewayKey = await queryPubKey(client, gatewayHash, gatewayAddress);

  const [contractHash, contractAddress] = await initializeContract(
    client,
    "contract.wasm.gz",
    gatewayHash,
    gatewayAddress,
    gatewayKey,
  );

  var clientInfo: [SecretNetworkClient, string, string, string, string, string, string] = [
    client,
    gatewayHash,
    gatewayAddress,
    contractHash,
    contractAddress,
    scrtRngHash,
    scrtRngAddress,
  ];
  return clientInfo;
}

async function generateKeys(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  scrtRngHash: string,
  scrtRngAddress: string,
) {

  const handle_msg = {
    key_gen: { 
      rng_hash: scrtRngHash,
      rng_addr: scrtRngAddress,
    },
  };
  // console.log(`Handle:\n${JSON.stringify(handle_msg, undefined ,2)}\n`);

  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: gatewayAddress,
      codeHash: gatewayHash,
      msg: handle_msg,
      sentFunds: [],
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 5000000,
    }
  );

  if (tx.code !== 0) {
    let error = (tx.rawLog.match(/(?<=\{)[^\}{]*(?=})/g)!).toString();
    // throw new Error(
    //   `Failed with the following error:\n ${tx.rawLog}`
    // );
    return error
  };

  gasTotal += tx.gasUsed;
  console.log(`generateKeys used \x1b[33m${tx.gasUsed}\x1b[0m gas\n`); 
}

async function gatewayTx(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  contractHash: string,
  contractAddress: string,
  gatewayPublicKey: string, // base64
  inputArray: [string, number, string],
  mnemonic: string,
): Promise<string> {
  const wallet = EthWallet.fromMnemonic(mnemonic); 
  const userPublicAddress: string = wallet.address;
  const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
  // console.log(`\n\x1b[34mEthereum Address: ${wallet.address}\n\x1b[34mPublic Key: ${userPublicKey}\n\x1b[34mPrivate Key: ${wallet.privateKey}\x1b[0m\n`);

  const userPrivateKeyBytes = arrayify(wallet.privateKey)
  const userPublicKeyBytes = arrayify(userPublicKey)
  const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, 'base64')
  const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer)

  const routing_info: Contract = {
    address: contractAddress,
    hash: contractHash
  };
  const sender: Sender = {
    address: userPublicAddress,
    public_key: Buffer.from(userPublicKeyBytes).toString('base64'),
  };
  const inputs = JSON.stringify(
    {
      address: userPublicAddress,
      name: inputArray[0],
      worth: inputArray[1],
      match_addr: inputArray[2],
    }
  );
  const payload: Payload = {
    data: inputs,
    routing_info: routing_info,
    sender: sender,
  };
  // console.log("Unencrypted Payload:");
  // console.log(payload);

  const plaintext = Buffer
    .from(JSON.stringify(payload));
  const nonce = arrayify(randomBytes(12));
  let ciphertext = Buffer
    .from(encrypt_payload(gatewayPublicKeyBytes, userPrivateKeyBytes, plaintext, nonce))
    .toString('base64');

  const payloadHash = createHash('sha256').update(ciphertext,'base64').digest();
  const payloadHash64 = payloadHash.toString('base64');
  // console.log(`\nPayload Hash is ${payloadHash.byteLength} bytes`);

  const payloadSignature = ecdsaSign(payloadHash, userPrivateKeyBytes).signature;
  const payloadSignature64 = Buffer.from(payloadSignature).toString('base64');
  // console.log(`Payload Signature is ${payloadSignature.byteLength} bytes\n`);

  const handle_msg = { 
    input: {
      inputs: { // TODO eliminate nesting if reasonable
        task_id: 1,
        handle: "submit_player",
        routing_info: routing_info,
        sender_info: sender,
        payload: ciphertext,
        nonce: Buffer.from(nonce).toString('base64'),
        payload_hash: payloadHash64,
        payload_signature: payloadSignature64,
        source_network: "ethereum",
      }
    }
  };

  // console.log("handle_msg:");
  // console.log(handle_msg);
  console.log(`Input:\n${JSON.stringify(handle_msg, undefined ,2)}\n`);

  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: gatewayAddress,
      codeHash: gatewayHash,
      msg: handle_msg,
      sentFunds: [],
    },
    {
      broadcastCheckIntervalMs: BROADCAST_MS,
      gasLimit: 200000,
    }
  );

  if (tx.code !== 0) {
    throw new Error(
      `Failed with the following error:\n ${tx.rawLog}`
    );
  };

  // Parsing the logs from the 'Output' handle

  let logs: {[index: string]:string} = {};
  const logKeys = [
    "source_network",
    "routing_info",
    "routing_info_hash",
    "routing_info_signature",
    "payload",
    "payload_hash",
    "payload_signature",
    "result",
    "result_hash",
    "result_signature",
    "packet_hash",
    "packet_signature",
    "task_id", 
    "task_id_hash",
    "task_id_signature",
  ];

  logKeys.forEach((key) => logs[key] = tx.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === key
  )!.value);

  console.log(`Output Logs:\n${JSON.stringify(logs, undefined, 2)}\n`);

  assert(logs["source_network"] == "secret");
  assert(logs["routing_info"] == "ethereum");
  assert(Buffer.from(logs["routing_info_hash"], 'base64').byteLength == 32);
  assert(Buffer.from(logs["routing_info_signature"], 'base64').byteLength == 64);
  assert(logs["payload"] == ciphertext);
  assert(Buffer.from(logs["payload_hash"], 'base64').byteLength == 32);
  assert(Buffer.from(logs["payload_signature"], 'base64').byteLength == 64);
  assert(logs["result"] == "{\"status\":\"success\"}" || "{\"richer\":\"bob\"}" || "{\"richer\":\"alice\"}");
  assert(Buffer.from(logs["result_hash"], 'base64').byteLength == 32);
  assert(Buffer.from(logs["result_signature"], 'base64').byteLength == 64);
  assert(Buffer.from(logs["packet_hash"], 'base64').byteLength == 32);
  assert(Buffer.from(logs["packet_signature"], 'base64').byteLength == 64);
  assert(logs["task_id"] == "1");
  assert(Buffer.from(logs["task_id_hash"], 'base64').byteLength == 32);
  assert(Buffer.from(logs["task_id_signature"], 'base64').byteLength == 64);

  gasTotal += tx.gasUsed;
  console.log(`gatewayTx used \x1b[33m${tx.gasUsed}\x1b[0m gas\n`);

  return logs["result"]
}

async function queryPubKey(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
): Promise<string> {
  type PublicKeyResponse = { key: Binary };

  const query_msg = { get_public_key: {} };
  // console.log(`Query:\n${JSON.stringify(query_msg, undefined ,2)}\n`);

  const response = (await client.query.compute.queryContract({
    contractAddress: gatewayAddress,
    codeHash: gatewayHash,
    query: query_msg,
  })) as PublicKeyResponse;

  // console.log(`Response:\n${JSON.stringify(response, undefined ,2)}\n`);
  return response.key
}

async function test_gateway_tx(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  contractHash: string,
  contractAddress: string,
) {
  const gatewayPublicKey = await queryPubKey(client, gatewayHash, gatewayAddress);
  
  const mnemonic1 = "youth then helmet clutch fresh piece raven demand purity wealth core holiday"; // 0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7
  const result1 = await gatewayTx(client, gatewayHash, gatewayAddress, contractHash, contractAddress, gatewayPublicKey, ["Alice", 5, "0x249C8753A9CB2a47d97A11D94b2179023B7aBCca"], mnemonic1);
  // this tx stores:
  // key: 0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7
  // value: Millionaire {
  //          name: Alice,
  //          worth: 5,
  //          match_addr: 0x249C8753A9CB2a47d97A11D94b2179023B7aBCca,
  //        }
  assert(result1 == "{\"status\":\"success\"}");
  
  const mnemonic2 = "destroy typical minor artist frame kitchen elegant pond gaze alien farm protect";  // 0x249C8753A9CB2a47d97A11D94b2179023B7aBCca
  const result2 = await gatewayTx(client, gatewayHash, gatewayAddress, contractHash, contractAddress, gatewayPublicKey, ["Bob", 10, "0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7"], mnemonic2);
  // this tx stores:
  // key: 0x249C8753A9CB2a47d97A11D94b2179023B7aBCca
  // value: Millionaire {
  //          name: Bob,
  //          worth: 10,
  //          match_addr: 0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7,
  //        }
  assert(result2 == "{\"result\":\"The richer of Bob and Alice is Bob\"}");
  
  const result3 = await gatewayTx(client, gatewayHash, gatewayAddress, contractHash, contractAddress, gatewayPublicKey, ["Alice", 580, "0x249C8753A9CB2a47d97A11D94b2179023B7aBCca"], mnemonic1);
  // this tx stores:
  // key: 0xb607FE9eF481950D47AEdf71ccB904Ff97806cF7
  // value: Millionaire {
  //          name: Alice,
  //          worth: 580,
  //          match_addr: 0x249C8753A9CB2a47d97A11D94b2179023B7aBCca,
  //        }
  assert(result3 == "{\"result\":\"The richer of Alice and Bob is Alice\"}");

  const result4 = await gatewayTx(client, gatewayHash, gatewayAddress, contractHash, contractAddress, gatewayPublicKey, ["Bob", 10, "someone else"], mnemonic2);
  // this tx stores:
  // key: 0x249C8753A9CB2a47d97A11D94b2179023B7aBCca
  // value: Millionaire {
  //          name: Bob,
  //          worth: 580,
  //          match_addr: someone else,
  //        }
  assert(result4 == "{\"status\":\"success\"}"); // meaning bob's entry has been updated but did not return a match
}

async function runTestFunction(
  tester: (
    client: SecretNetworkClient,
    gatewayHash: string,
    gatewayAddress: string,
    contractHash: string,
    contractAddress: string,
    scrtRngHash: string,
    scrtRngAddress: string,
  ) => void,
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  contractHash: string,
  contractAddress: string,
  scrtRngHash: string,
  scrtRngAddress: string,
) {
  console.log(`[  \x1b[35mTEST\x1b[0m  ] ${tester.name}\n`);
  await tester(client, gatewayHash, gatewayAddress, contractHash, contractAddress, scrtRngHash, scrtRngAddress);
  console.log(`[   \x1b[32mOK\x1b[0m   ] ${tester.name}\n`);
}

(async () => {
  const [client, gatewayHash, gatewayAddress, contractHash, contractAddress, scrtRngHash, scrtRngAddress] =
    await initializeAndUploadContract();
    // console.log(`TOTAL GAS USED FOR UPLOAD AND INIT: \x1b[33;1m${gasTotal}\x1b[0m gas\n`)
    
  await runTestFunction(
    test_gateway_tx,
    client,
    gatewayHash, 
    gatewayAddress, 
    contractHash, 
    contractAddress,
    scrtRngHash,
    scrtRngAddress,
  );
})();
