import fs from "fs";
import { Wallet, SecretNetworkClient } from "secretjs";
import { computeAddress } from "ethers/lib/utils";
import 'dotenv/config'

var mnemonic = process.env.MNEMONIC!;
var endpoint = process.env.LCD_WEB_URL!;
var chainId = process.env.CHAIN_ID!;

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
      admin: client.address,
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
async function initializeAndUploadContract(gatewayHash: string,
  gatewayAddress: string,
  gatewayPublicKey: string) {
  const client = await initializeClient(endpoint, chainId);
  let balance = await getScrtBalance(client);
  const gatewayPublicKeyBytes = Buffer.from(gatewayPublicKey.substring(2), 'hex').toString('base64');
  const [contractHash, contractAddress] = await initializeContract(
    client,
    "../TNLS-Samples/Storage/contract.wasm.gz",
    gatewayHash,
    gatewayAddress,
    gatewayPublicKeyBytes,
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

(async () => {
  const [client, gatewayHash, gatewayAddress, contractHash, contractAddress] =
    await initializeAndUploadContract("012dd8efab9526dec294b6898c812ef6f6ad853e32172788f54ef3c305c1ecc5","secret10ex7r7c4y704xyu086lf74ymhrqhypayfk7fkj","0x046d0aac3ef10e69055e934ca899f508ba516832dc74aa4ed4d741052ed5a568774d99d3bfed641a7935ae73aac8e34938db747c2f0e8b2aa95c25d069a575cc8b");
})();
