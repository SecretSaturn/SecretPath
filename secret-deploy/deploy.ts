import fs from "fs";
import { Wallet, SecretNetworkClient } from "secretjs";
import { computeAddress } from "ethers/lib/utils";
import 'dotenv/config'

var mnemonic = process.env.MNEMONIC!;
var endpoint = process.env.LCD_WEB_URL!;
var chainId = process.env.CHAIN_ID!;

type PublicKeyResponse = { encryption_key: string, verification_key: string };

// Returns a client with which we can interact with secret network
const initializeClient = async (endpoint: string, chainId: string) => {
  let wallet = new Wallet(mnemonic);
  const accAddress = wallet.address;
  const client = new SecretNetworkClient({
    // Create a client to interact with the network
    url: endpoint,
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
) => {
  const wasmCode = fs.readFileSync(contractPath);
  console.log("\nUploading gateway contract");

  const uploadReceipt = await client.tx.compute.storeCode(
    {
      wasm_byte_code: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      gasLimit: 3000000,
      gasPriceInFeeDenom: 0.05,
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
  const {code_hash: contractCodeHash} = await client.query.compute.codeHashByCodeId({code_id: codeId.toString()});
  
  console.log("Gateway contract code id: ", codeId);
  console.log(`Gateway contract code hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      code_id: codeId,
      init_msg: { 
      },
      code_hash: contractCodeHash,
      label: "test_secret_gateway" + Math.ceil(Math.random() * 10000), // The label should be unique for every contract, add random string in order to maintain uniqueness
    },
    {
      gasLimit: 100000,
      gasPriceInFeeDenom: 0.05,
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

  const gatewayInfo: [string, string] = [contractCodeHash as any, contractAddress];
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
      wasm_byte_code: wasmCode,
      sender: client.address,
      source: "",
      builder: "",
    },
    {
      gasLimit: 1500000,
      gasPriceInFeeDenom: 0.05,
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
  const {code_hash:contractCodeHash} = await client.query.compute.codeHashByCodeId({code_id:codeId.toString()});
  
  console.log("Sample contract code id: ", codeId);
  console.log(`Sample contract code hash: ${contractCodeHash}`);

  const contract = await client.tx.compute.instantiateContract(
    {
      sender: client.address,
      code_id: codeId,
      init_msg: {
        gateway_hash: gatewayHash,
        gateway_address: gatewayAddress,
        gateway_key: gatewayKey,
      },
      code_hash: contractCodeHash,
      label: "test_sample_contract" + Math.ceil(Math.random() * 10000),
    },
    {
      gasLimit: 100000,
      gasPriceInFeeDenom: 0.05,
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

  var contractInfo: [string, string] = [contractCodeHash as any, contractAddress];
  return contractInfo;
};

async function getScrtBalance(userCli: SecretNetworkClient) {
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
  const [gatewayHash, gatewayAddress] = await initializeGateway(
    client,
    "../TNLS-Gateways/secret/contract.wasm.gz",
  );
  console.log(`Sending query: {"get_public_keys": {} }`);
  const gatewayKeys = await queryPubKeys(client, gatewayHash, gatewayAddress);
  const gatewayPublicKey = Buffer.from(gatewayKeys.verification_key.substring(2), 'hex').toString('base64');
  const [contractHash, contractAddress] = await initializeContract(
    client,
    "../TNLS-Samples/RNG/contract.wasm.gz",
    gatewayHash,
    gatewayAddress,
    gatewayPublicKey,
  );

  var clientInfo: [SecretNetworkClient, string, string, string, string] = [
    client,
    gatewayHash,
    gatewayAddress,
    contractHash,
    contractAddress,
  ];
  return clientInfo;
}

async function queryPubKeys(
  client: SecretNetworkClient,
  gatewayHash: string,
  gatewayAddress: string,
): Promise<PublicKeyResponse> {
  const response = (await client.query.compute.queryContract({
    contract_address: gatewayAddress,
    code_hash: gatewayHash,
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
  const [client, gatewayHash, gatewayAddress, contractHash, contractAddress] =
    await initializeAndUploadContracts();
})();
