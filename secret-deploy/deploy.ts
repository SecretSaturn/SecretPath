import fs from "fs";
import { Wallet, SecretNetworkClient } from "secretjs";
import { computeAddress } from "ethers/lib/utils";
import 'dotenv/config'

var mnemonic = process.env.MNEMONIC!;
var endpoint = process.env.GRPC_WEB_URL!;
var chainId = process.env.CHAIN_ID!;

type PublicKeyResponse = { encryption_key: string, verification_key: string };

// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  let wallet = new Wallet(mnemonic);
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
  const contractCodeHash = await client.query.compute.codeHash(codeId);
  
  console.log("Gateway contract code id: ", codeId);
  console.log(`Gateway contract code hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      codeId,
      initMsg: { 
        entropy: "TNLS rocks",
        rng_hash: scrtRngHash,
        rng_addr: scrtRngAddress,
      },
      codeHash: contractCodeHash,
      label: "test_secret_gateway" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      gasLimit: 5000000,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  };

  const contractAddress = contract.arrayLog!.find(
    (log) => log.type === "message" && log.key === "contract_address"
  )!.value;

  fs.writeFileSync("secret_gateway.log",
    `${codeId}\n${contractCodeHash}\n${contractAddress}\n`);
  
  console.log(`Gateway contract address: ${contractAddress}\n`);
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  var gatewayInfo: [string, string] = [contractCodeHash, contractAddress];
  return gatewayInfo;
};

const initializeContract = async (
  client: SecretNetworkClient,
  contractPath: string,
  gatewayHash: string,
  gatewayAddress: string,
  gatewayKey: string,
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("\nUploading sample contract");

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
  };

  const codeIdKv = uploadReceipt.jsonLog![0].events[0].attributes.find(
    (a: any) => {
      return a.key === "code_id";
    }
  );

  console.log(`Upload used \x1b[33m${uploadReceipt.gasUsed}\x1b[0m gas\n`);

  const codeId = Number(codeIdKv!.value);
  const contractCodeHash = await client.query.compute.codeHash(codeId);
  
  console.log("Sample contract code id: ", codeId);
  console.log(`Sample contract code hash: ${contractCodeHash}`);

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
      label: "test_sample_contract" + Math.ceil(Math.random() * 10000),
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

  fs.writeFileSync("secret_sample.log",
    `${codeId}\n${contractCodeHash}\n${contractAddress}\n`);

  console.log(`Sample contract address: ${contractAddress}\n`);
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas`);

  var contractInfo: [string, string] = [contractCodeHash, contractAddress];
  return contractInfo;
};

async function getScrtBalance(userCli: SecretNetworkClient): Promise<string> {
  let balanceResponse = await userCli.query.bank.balance({
    address: userCli.address,
    denom: "uscrt",
  });
  return balanceResponse.balance!.amount;
}

// Initialization procedure
async function initializeAndUploadContracts() {
  const client = await initializeClient(endpoint, chainId);
  let balance = await getScrtBalance(client);
  console.log(`Current SCRT Balance: ${balance}`)
  const scrtRngHash = "15D8766782EE5434510FBA567E8376A7E39155B16D1CA2308FD2D8BB28AFB05C";
  const scrtRngAddress = "secret14yqa7fux3308kknsmdft8azmkje5krzwz570q9";
  const [gatewayHash, gatewayAddress] = await initializeGateway(
    client,
    "../TNLS-Gateways/secret/contract.wasm.gz",
    scrtRngHash,
    scrtRngAddress,
  );
  console.log(`Retrieving random number...`);
  await rngTx(client, gatewayHash, gatewayAddress, scrtRngHash, scrtRngAddress);
  console.log(`Sending query: {"get_public_keys": {} }`);
  const gatewayKeys = await queryPubKeys(client, gatewayHash, gatewayAddress);
  const gatewayPublicKey = Buffer.from(gatewayKeys.verification_key.substring(2), 'hex').toString('base64');
  const [contractHash, contractAddress] = await initializeContract(
    client,
    "../TNLS-Gateways/secret/tests/example-private-contract/contract.wasm.gz",
    gatewayHash,
    gatewayAddress,
    gatewayPublicKey,
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
};

async function queryPubKeys(
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
  fs.appendFileSync("secret_gateway.log",
    `${response.encryption_key}\n${computeAddress(response.verification_key)}\n`);
  return response;
};

(async () => {
  const [client, gatewayHash, gatewayAddress, contractHash, contractAddress, scrtRngHash, scrtRngAddress] =
    await initializeAndUploadContracts();
})();
