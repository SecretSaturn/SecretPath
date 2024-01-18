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
    "../TNLS-Samples/RNG/contract.wasm.gz",
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
    await initializeAndUploadContract("bd6253cde923dc577e7c421d26fc74bd78aad4212bc6bdab4751e2764d678627","secret1mj9ana8lwh2chlalfjw6mjalgynkau2z893akk","0x04173a82969fec6b375013438a650316c7c0ece9bdb0646057c34c61e25d752e6b851d56200ea3dd521f305d7dddff23ee2d40bf1d1f4bc8c592852eac9e7c8a74");
})();
