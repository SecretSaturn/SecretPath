import axios from "axios";
import { Wallet, SecretNetworkClient, fromUtf8, fromHex } from "secretjs";
import fs from "fs";
import assert from "assert";
import { PreExecutionMsg, Payload, Binary } from "./GatewayContract";
import { ecdsaSign, publicKeyConvert } from "secp256k1";
import { Wallet as EthWallet } from "ethers";
import { arrayify, hexlify, SigningKey, computeAddress, recoverAddress, recoverPublicKey, keccak256 } from "ethers/lib/utils";
import sha3 from "js-sha3";
import { createHash, randomBytes } from 'crypto';
import { encrypt_payload } from './encrypt-payload/pkg'
import 'dotenv/config'

var mnemonic: string;
var endpoint: string = "http://localhost:9091";
var chainId: string = "secretdev-1";

// uncomment if using .env file
// mnemonic = process.env.MNEMONIC!;
// endpoint = process.env.GRPC_WEB_URL!;
// chainId = process.env.CHAIN_ID!;

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
  console.log("\nUploading gateway contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
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
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  var gatewayInfo: [string, string] = [contractCodeHash, contractAddress];
  return gatewayInfo;
};

const initializeScrtRng = async (
  client: SecretNetworkClient,
  contractPath: string,
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("\nUploading scrt-rng contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
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
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas`);

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
  console.log("\nUploading example contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasmByteCode: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
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

  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas`);

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
  console.error(`got tokens from faucet: ${balance}`);
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

  console.log(`Retrieving random number...`);
  await rngTx(client, gatewayHash, gatewayAddress, scrtRngHash, scrtRngAddress);
  console.log(`Sending query: {"get_public_keys": {} }`);
  const gatewayKeys = await queryPubKey(client, gatewayHash, gatewayAddress);

  const gatewayKey = Buffer.from(gatewayKeys.verification_key.substring(2), 'hex').toString('base64')

  const [contractHash, contractAddress] = await initializeContract(
    client,
    "../../TNLS-Gateways/secret/tests/example-private-contract/contract.wasm.gz",
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

async function rngTx(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  scrtRngHash: string,
  scrtRngAddress: string,
) {
  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: gatewayAddress,
      codeHash: gatewayHash,
      msg: {
        key_gen: { 
          rng_hash: scrtRngHash,
          rng_addr: scrtRngAddress,
        },
      },
      sentFunds: [],
    },
    {
      gasLimit: 5000000,
    }
  );

  if (tx.code !== 0) {
    throw new Error(
      `Failed with the following error:\n ${tx.rawLog}`
    );
  };

  console.log(`"key_gen" used \x1b[33m${tx.gasUsed}\x1b[0m gas\n`);
}

async function gatewayTx(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  contractHash: string,
  contractAddress: string,
  gatewayPublicKey: string, // base64, encryption key
) {
  const wallet = EthWallet.createRandom(); 
  const userPublicAddress: string = wallet.address;
  const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
  // console.log(`\n\x1b[34mEthereum Address: ${wallet.address}\n\x1b[34mPublic Key: ${userPublicKey}\n\x1b[34mPrivate Key: ${wallet.privateKey}\x1b[0m\n`);

  const userPrivateKeyBytes = arrayify(wallet.privateKey)
  const userPublicKeyBytes = arrayify(userPublicKey)
  const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, 'base64')
  const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer)
  
  const inputs = JSON.stringify({"my_value": 1});
  const routing_info = contractAddress;
  const routing_code_hash = contractHash;
  const user_address = userPublicAddress;
  const user_key = Buffer.from(userPublicKeyBytes).toString('base64');

  const payload: Payload = {
    data: inputs,
    routing_info: routing_info,
    routing_code_hash: routing_code_hash,
    user_address: user_address,
    user_key: user_key
  };
  console.log("Unencrypted Payload:");
  console.log(payload);

  const plaintext = Buffer
    .from(JSON.stringify(payload));
  const nonce = arrayify(randomBytes(12));
  let ciphertext = Buffer
    .from(encrypt_payload(gatewayPublicKeyBytes, userPrivateKeyBytes, plaintext, nonce))
    .toString('base64');

  const payloadHash = createHash('sha256').update(ciphertext,'base64').digest();
  // const payloadHash64 = payloadHash.toString('base64');
  const payloadSignature = ecdsaSign(payloadHash, userPrivateKeyBytes).signature;
  // const payloadSignature64 = Buffer.from(payloadSignature).toString('base64');

  const user_pubkey = publicKeyConvert(arrayify(recoverPublicKey(arrayify(payloadHash), payloadSignature)),true)
  console.log(`Recovered user_pubkey: ${hexlify(user_pubkey)}`)

  const handle_msg: PreExecutionMsg = {
    task_id: 1,
    handle: "add_one",
    routing_info: routing_info,
    routing_code_hash: routing_code_hash,
    user_address: user_address,
    user_key: user_key,
    user_pubkey: Buffer.from(user_pubkey).toString('base64'),
    payload: ciphertext,
    nonce: Buffer.from(nonce).toString('base64'),
    payload_hash: payloadHash.toString('base64'),
    payload_signature: Buffer.from(payloadSignature).toString('base64'),
    source_network: "ethereum",
  };
  console.log("handle_msg:");
  console.log(handle_msg);

  const tx = await client.tx.compute.executeContract(
    {
      sender: client.address,
      contractAddress: gatewayAddress,
      codeHash: gatewayHash,
      msg: {
        input: { inputs: handle_msg }, // TODO eliminate nesting if possible
      },
      sentFunds: [],
    },
    {
      gasLimit: 500000,
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
    "task_destination_network",
    "task_id", 
    "payload_hash",
    "payload_signature",
    "result",
    "result_hash",
    "result_signature",
    "packet_hash",
    "packet_signature",
  ];

  logKeys.forEach((key) => logs[key] = tx.arrayLog!.find(
    (log) => log.type === "wasm" && log.key === key
  )!.value);

  console.log("\nOutput Logs:");
  console.log(logs);

  console.log('\nTesting recoverAddress on each signature:')
  const test1 = recoverAddress(logs["payload_hash"], logs["payload_signature"]);
  const test2 = recoverAddress(logs["result_hash"], logs["result_signature"]);
  const test3 = recoverAddress(logs["packet_hash"], logs["packet_signature"]);
  [test1, test2, test3].forEach(element => {
    console.log(element)
  });

  assert(logs["source_network"] == "secret");
  assert(logs["task_destination_network"] == "ethereum");
  assert(logs["task_id"] == "1");
  assert(fromHex(logs["payload_hash"].substring(2)).byteLength == 32);
  assert(fromHex(logs["payload_signature"].substring(2)).byteLength == 65);
  assert(logs["result"] == "0x7b226d795f76616c7565223a327d");
  assert(fromHex(logs["result_hash"].substring(2)).byteLength == 32);
  assert(fromHex(logs["result_signature"].substring(2)).byteLength == 65);
  assert(fromHex(logs["packet_hash"].substring(2)).byteLength == 32);
  assert(fromHex(logs["packet_signature"].substring(2)).byteLength == 65);

  console.log(`inputTx used \x1b[33m${tx.gasUsed}\x1b[0m gas`);
}

type PublicKeyResponse = { encryption_key: Binary, verification_key: Binary };

async function queryPubKey(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
): Promise<PublicKeyResponse> {

  const response = (await client.query.compute.queryContract({
    contractAddress: gatewayAddress,
    codeHash: gatewayHash,
    query: { get_public_keys: {} },
  })) as PublicKeyResponse;

  console.log(`\x1b[32mEncryption key: ${response.encryption_key}\x1b[0m`);
  console.log(`\x1b[32mPublic key: ${response.verification_key}\x1b[0m`);
  console.log(`\x1b[34;1mEth Address: ${computeAddress(response.verification_key)}\x1b[0m`);

  return response
}

async function test_gateway_tx(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
  contractHash: string,
  contractAddress: string,
  scrtRngHash: string,
  scrtRngAddress: string,
) {
  console.log(`Sending query: {"get_public_keys": {} }`);
  const gatewayPublicKey = await queryPubKey(client, gatewayHash, gatewayAddress);
  await gatewayTx(client, gatewayHash, gatewayAddress, contractHash, contractAddress, gatewayPublicKey.encryption_key);
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
  console.log(`\n[  \x1b[35mTEST\x1b[0m  ] ${tester.name}\n`);
  await tester(client, gatewayHash, gatewayAddress, contractHash, contractAddress, scrtRngHash, scrtRngAddress);
  console.log(`\n[   \x1b[32mOK\x1b[0m   ] ${tester.name}\n`);
}

(async () => {
  const [client, gatewayHash, gatewayAddress, contractHash, contractAddress, scrtRngHash, scrtRngAddress] =
    await initializeAndUploadContract();

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
