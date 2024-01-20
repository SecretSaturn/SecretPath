import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x874303B788c8A13a39EFA38ab6C3b77cd4578129'
    const routing_contract = "secret1n8jh8qvjhu5ktce7v7ntlqac7u7wle6lvqnw38"
    const routing_code_hash = "2a8c936d011446c0ae1f2503b4fb86455b7dc2c6899a56bd74edf9636f9517db"

    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);

    // generating ephemeral keys
    const wallet = ethers.Wallet.createRandom();
    const userPrivateKeyBytes = arrayify(wallet.privateKey);
    const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
    const userPublicKeyBytes = arrayify(userPublicKey)
    //

    //unencrypted input 
    const gatewayPublicKey = "Ahc6gpaf7Gs3UBNDimUDFsfA7Om9sGRgV8NMYeJddS5r"; 
    const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, "base64");
    const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        const [myAddress] = await provider.send("eth_requestAccounts", []);
        await (window as any).ethereum.request({
            method: 'wallet_switchEthereumChain',
            params: [{ chainId: '0xAA36A7' }], // chainId must be in hexadecimal numbers
          });
        
        const numWords = document.querySelector<HTMLFormElement>('#input1')?.value;
        const callback_gas_limit = document.querySelector<HTMLFormElement>('#input2')?.value;
        
        const data = JSON.stringify({
            numWords: Number(numWords)
        })

        const user_address = myAddress
        const user_key = Buffer.from(userPublicKeyBytes)

        // create the abi interface and encode the function data
        const abi = [{"type":"function","name":"callback","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_result","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"increaseTaskId","inputs":[{"name":"_newTaskId","type":"uint256","internalType":"uint256"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"initialize","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"postExecution","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_sourceNetwork","type":"string","internalType":"string"},{"name":"_info","type":"tuple","internalType":"struct Gateway.PostExecutionInfo","components":[{"name":"payload_hash","type":"bytes32","internalType":"bytes32"},{"name":"packet_hash","type":"bytes32","internalType":"bytes32"},{"name":"callback_address","type":"bytes20","internalType":"bytes20"},{"name":"callback_selector","type":"bytes4","internalType":"bytes4"},{"name":"callback_gas_limit","type":"bytes4","internalType":"bytes4"},{"name":"packet_signature","type":"bytes","internalType":"bytes"},{"name":"result","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"requestRandomness","inputs":[{"name":"_numWords","type":"uint32","internalType":"uint32"},{"name":"_callbackGasLimit","type":"uint32","internalType":"uint32"}],"outputs":[{"name":"requestId","type":"uint256","internalType":"uint256"}],"stateMutability":"payable"},{"type":"function","name":"send","inputs":[{"name":"_payloadHash","type":"bytes32","internalType":"bytes32"},{"name":"_userAddress","type":"address","internalType":"address"},{"name":"_routingInfo","type":"string","internalType":"string"},{"name":"_info","type":"tuple","internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"task_destination_network","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"payable"},{"type":"function","name":"taskId","inputs":[],"outputs":[{"name":"","type":"uint256","internalType":"uint256"}],"stateMutability":"view"},{"type":"function","name":"tasks","inputs":[{"name":"","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"payload_hash_reduced","type":"bytes31","internalType":"bytes31"},{"name":"completed","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"event","name":"ComputedResult","inputs":[{"name":"taskId","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"result","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"Initialized","inputs":[{"name":"version","type":"uint64","indexed":false,"internalType":"uint64"}],"anonymous":false},{"type":"event","name":"logNewTask","inputs":[{"name":"task_id","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"source_network","type":"string","indexed":false,"internalType":"string"},{"name":"user_address","type":"address","indexed":false,"internalType":"address"},{"name":"routing_info","type":"string","indexed":false,"internalType":"string"},{"name":"payload_hash","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"info","type":"tuple","indexed":false,"internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"task_destination_network","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]}],"anonymous":false},{"type":"error","name":"CallbackError","inputs":[]},{"type":"error","name":"InvalidInitialization","inputs":[]},{"type":"error","name":"InvalidPacketSignature","inputs":[]},{"type":"error","name":"InvalidPayloadHash","inputs":[]},{"type":"error","name":"InvalidSignature","inputs":[]},{"type":"error","name":"InvalidSignatureLength","inputs":[]},{"type":"error","name":"InvalidSignatureSValue","inputs":[]},{"type":"error","name":"NotInitializing","inputs":[]},{"type":"error","name":"TaskAlreadyCompleted","inputs":[]}]
        const iface= new ethers.utils.Interface( abi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))

        const _callbackAddress = publicClientAddress.toLowerCase();
        const _callbackSelector = iface.getSighash(iface.getFunction("callback"))
        const _callbackGasLimit = Number(callback_gas_limit)

        const thePayload = JSON.stringify({
            data: data,
            routing_info: routing_contract,
            routing_code_hash: routing_code_hash,
            user_address: user_address,
            user_key: user_key.toString('base64'),
            callback_address: Buffer.from(arrayify(_callbackAddress)).toString('base64'),
            callback_selector: Buffer.from(arrayify(_callbackSelector)).toString('base64'),
            callback_gas_limit: _callbackGasLimit,
        })
        console.log(thePayload)
        
        const plaintext = Buffer.from(thePayload);
        const nonce = secureRandom(12, { type: "Uint8Array" });
        const handle = "request_random"

        const ciphertext = Buffer.from(
        encrypt_payload(
             gatewayPublicKeyBytes,
             userPrivateKeyBytes,
             plaintext,
             nonce
         ));

        //if not encrypted, just use the plaintext bytes
        //const ciphertext = plaintext
    
        //get Metamask to sign the payloadhash with personal_sign
        const ciphertextHash = keccak256(Buffer.from(ciphertext))
        //this is what metamask really signs with personal_sign, it prepends the ethereum signed message here
        const payloadHash = keccak256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n32"),Buffer.from(ciphertextHash.substring(2),'hex')]))
        //this is what we provide to metamask
        const msgParams = ciphertextHash;
        const from = myAddress;
        const params = [from, msgParams];
        const method = 'personal_sign';
        console.log(`Payload Hash: ${payloadHash}`)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${thePayload}</p>

        <h2>TNLS Payload</h2>
        <p>${ciphertext.toString('base64')}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>
        `

        const payloadSignature = await provider.send(method, params)
        console.log(`Payload Signature: ${payloadSignature}`)

        const user_pubkey = recoverPublicKey(payloadHash, payloadSignature)
        console.log(`Recovered public key: ${user_pubkey}`)
        console.log(`Verify this matches the user address: ${computeAddress(user_pubkey)}`)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${thePayload}</p>

        <h2>TNLS Payload</h2>
        <p>${ciphertext.toString('base64')}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>

        <h2>Payload Signature</h2>
        <p>${payloadSignature}<p>
        `

        // function data to be abi encoded
        const _userAddress = myAddress
        const _routingInfo = routing_contract
        const _payloadHash = payloadHash
        const _info = {
            user_key: hexlify(user_key),
            user_pubkey: user_pubkey, 
            routing_code_hash: routing_code_hash,
            task_destination_network: "secret-4",
            handle: handle,
            nonce: hexlify(nonce),
            payload: hexlify(ciphertext),
            payload_signature: payloadSignature
        }
                        
 
        console.log(`_userAddress: ${_userAddress}
        _routingInfo: ${_routingInfo} 
        _payloadHash: ${_payloadHash} 
        _info: ${JSON.stringify(_info)}
        _callbackAddress: ${_callbackAddress},
        _callbackSelector: ${_callbackSelector} ,
        _callbackGasLimit: ${_callbackGasLimit}`)

        const functionData = iface.encodeFunctionData("send",
            [
                _payloadHash,
                _userAddress,
                _routingInfo,
                _info,
            ]
        )
        console.log(functionData)

        const tx_params = [
            {
                gas: '0x249F0', // 150000
                to: publicClientAddress,
                from: myAddress,
                value: '0x00', // 0
                data: functionData, // TODO figure out what this data is meant to be
            },
          ];

        const txHash = await provider.send("eth_sendTransaction", tx_params);
        console.log(txHash)

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        <h2>Raw Payload</h2>
        <p>${thePayload}</p>

        <h2>TNLS Payload</h2>
        <p>${ciphertext.toString('base64')}</p>

        <h2>Payload Hash</h2>
        <p>${payloadHash}<p>

        <h2>Payload Signature</h2>
        <p>${payloadSignature}<p>

        <h2>Other Info</h2>
        <p>

        <b>Public key used during encryption:</b> ${userPublicKey} <br>
        <b>Nonce used during encryption:</b> ${nonce} <br>

        </p>

        <h2>Transaction Parameters</h2>
        <p><b>Tx Hash: </b><a href="https://polygonscan.com/tx/${txHash}" target="_blank">${txHash}</a></p>
        <p><b>Gateway Address (to check the postExecution callback) </b><a href="https://polygonscan.com/address/${publicClientAddress}" target="_blank">${publicClientAddress}</a></p>
        <p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>
        `
    })
}
//  <p><b>Tx Hash: </b><a href="https://sepolia.etherscan.io/tx/${txHash}" target="_blank">${txHash}</a></p>
//<p><b>Gateway Address (to check the postExecution callback) </b><a href="https://sepolia.etherscan.io/address/${publicClientAddress}" target="_blank">${publicClientAddress}</a></p>
//<p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>