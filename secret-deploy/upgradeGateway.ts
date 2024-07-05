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

const upgradeGateway = async (
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

  const contractAddress = "secret1vrxpv6a44v3uk6kyxl0q6j8yjjzwltm2g975nh"
  const contract = await client.tx.compute.migrateContract(
    {
      sender: client.address,
      contract_address: contractAddress,
      code_id: codeId,
      msg: {
        migrate:{}
      },
    },
    {
      gasLimit: 300000,
      gasPriceInFeeDenom: 0.05,
    }
  );

  if (contract.code !== 0) {
    throw new Error(
      `Failed to instantiate the contract with the following error ${contract.rawLog}`
    );
  };

  fs.writeFileSync("secret_gateway.log",
    `${codeId}\n${contractCodeHash}\n${contractAddress}\n`);
  
  console.log(`Gateway contract address: ${contractAddress}\n`);
  console.log(`Init used \x1b[33m${contract.gasUsed}\x1b[0m gas\n`);

  const gatewayInfo: [string, string] = [contractCodeHash as any, contractAddress];
  return gatewayInfo;
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
  const [gatewayHash, gatewayAddress] = await upgradeGateway(
    client,
    "../TNLS-Gateways/secret/contract.wasm.gz",
  );


  var clientInfo: [SecretNetworkClient, string, string] = [
    client,
    gatewayHash,
    gatewayAddress,
  ];
  return clientInfo;
}

(async () => {
  const [client, gatewayHash, gatewayAddress] =
    await initializeAndUploadContracts();
})();
