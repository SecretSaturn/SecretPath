//import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x5749b422f34ec5177f09CF7c321fbC73546EB8C8'
    const routing_info = "secret1guad7jcwdata8lmrr8c4v2av8y32fd97pf9hl0"
    const routing_code_hash = "288e2d7d77122540cefb1264002f101f0375e3dd77618668bee097ef0d2acf3f"

    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);

    // generating ephemeral keys
    const wallet = ethers.Wallet.createRandom();
   // const userPrivateKeyBytes = arrayify(wallet.privateKey);
    const userPublicKey: string = new SigningKey(wallet.privateKey).compressedPublicKey;
    const userPublicKeyBytes = arrayify(userPublicKey)
    //

    //unencrypted input 
    //const gatewayPublicKey = "BMbTfKh++E0vBd+jXejZvMc8hZNGEzZ8JjMgr8Wbc76zEHqQbcgV1+6z1G8GsmwaF18L7CCGbx6phF9Sbni8WxQ="; // TODO get this key
    //const gatewayPublicKeyBuffer = Buffer.from(gatewayPublicKey, "base64");
    //const gatewayPublicKeyBytes = arrayify(gatewayPublicKeyBuffer);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        const [myAddress] = await provider.send("eth_requestAccounts", []);

        const data = JSON.stringify({
        })

        const user_address = myAddress
        const user_key = Buffer.from(userPublicKeyBytes)

        
        const thePayload = JSON.stringify({
            data: data,
            routing_info: routing_info,
            routing_code_hash: routing_code_hash,
            user_address: user_address,
            user_key: user_key.toString('base64'),
        })
        
        const plaintext = Buffer.from(thePayload);
        const nonce = secureRandom(12, { type: "Uint8Array" });
        const handle = "request_random"

        // const ciphertext = Buffer.from(
        // encrypt_payload(
        //     gatewayPublicKeyBytes,
        //     userPrivateKeyBytes,
        //     plaintext,
        //     nonce
        // ));

        const ciphertext = plaintext
    
        // // get Metamask to sign the payloadHash with eth_sign
        // const payloadHash = keccak256(ciphertext)
        // const msgParams = payloadHash
        // const from = myAddress;
        // const params = [from, msgParams];
        // const method = 'eth_sign';

        //get Metamask to sign the payload with personal_sign
        const ciphertextHash = keccak256(Buffer.from(ciphertext))
        //this is what metamask really signs with personal_sign
        const payloadHash = keccak256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n32"),Buffer.from(ciphertextHash.substring(2),'hex')]))
        //this is what we provide to metamask
        const msgParams = ciphertextHash;
        const from = myAddress;
        const params = [from, ciphertextHash];
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
        //const _sourceNetwork = "ethereum"
        const _sourceNetwork = "ethereum"
        const _routingInfo = routing_info
        const _payloadHash = payloadHash
        const _info = {
            user_key: hexlify(user_key),
            user_pubkey: user_pubkey,  // need the updated ABI before including this
            routing_code_hash: routing_code_hash,
            handle: handle,
            nonce: hexlify(nonce),
            payload: hexlify(ciphertext),
            payload_signature: payloadSignature
        }

        console.log(`_userAddress: ${_userAddress}
            _sourceNetwork: ${_sourceNetwork} 
            _routingInfo: ${_routingInfo} 
            _payloadHash: ${_payloadHash} 
            _info: ${JSON.stringify(_info)}`)
                
        // create the abi interface and encode the function data
        const abi = [{"type":"function","name":"callback","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_result","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"initialize","inputs":[{"name":"_masterVerificationAddress","type":"address","internalType":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"masterVerificationAddress","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"postExecution","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_sourceNetwork","type":"string","internalType":"string"},{"name":"_info","type":"tuple","internalType":"struct Gateway.PostExecutionInfo","components":[{"name":"payload_hash","type":"bytes32","internalType":"bytes32"},{"name":"result","type":"bytes","internalType":"bytes"},{"name":"result_hash","type":"bytes32","internalType":"bytes32"},{"name":"result_signature","type":"bytes","internalType":"bytes"},{"name":"packet_hash","type":"bytes32","internalType":"bytes32"},{"name":"packet_signature","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"preExecution","inputs":[{"name":"_task","type":"tuple","internalType":"struct Gateway.Task","components":[{"name":"callback_address","type":"address","internalType":"address"},{"name":"callback_selector","type":"bytes4","internalType":"bytes4"},{"name":"callback_gas_limit","type":"uint32","internalType":"uint32"},{"name":"user_address","type":"address","internalType":"address"},{"name":"source_network","type":"string","internalType":"string"},{"name":"routing_info","type":"string","internalType":"string"},{"name":"payload_hash","type":"bytes32","internalType":"bytes32"},{"name":"completed","type":"bool","internalType":"bool"}]},{"name":"_info","type":"tuple","internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"route","inputs":[{"name":"","type":"string","internalType":"string"}],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"send","inputs":[{"name":"_userAddress","type":"address","internalType":"address"},{"name":"_sourceNetwork","type":"string","internalType":"string"},{"name":"_routingInfo","type":"string","internalType":"string"},{"name":"_payloadHash","type":"bytes32","internalType":"bytes32"},{"name":"_info","type":"tuple","internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]},{"name":"_callbackAddress","type":"address","internalType":"address"},{"name":"_callbackSelector","type":"bytes4","internalType":"bytes4"},{"name":"_callbackGasLimit","type":"uint32","internalType":"uint32"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"tasks","inputs":[{"name":"","type":"uint256","internalType":"uint256"}],"outputs":[{"name":"payload_hash","type":"bytes32","internalType":"bytes32"},{"name":"callback_address","type":"address","internalType":"address"},{"name":"callback_selector","type":"bytes4","internalType":"bytes4"},{"name":"callback_gas_limit","type":"uint32","internalType":"uint32"},{"name":"completed","type":"bool","internalType":"bool"}],"stateMutability":"view"},{"type":"function","name":"updateRoute","inputs":[{"name":"_route","type":"string","internalType":"string"},{"name":"_verificationAddress","type":"address","internalType":"address"},{"name":"_signature","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"ComputedResult","inputs":[{"name":"taskId","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"result","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"logCompletedTask","inputs":[{"name":"task_id","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"payload_hash","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"result_hash","type":"bytes32","indexed":false,"internalType":"bytes32"}],"anonymous":false},{"type":"event","name":"logNewTask","inputs":[{"name":"task_id","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"source_network","type":"string","indexed":false,"internalType":"string"},{"name":"user_address","type":"address","indexed":false,"internalType":"address"},{"name":"routing_info","type":"string","indexed":false,"internalType":"string"},{"name":"routing_code_hash","type":"string","indexed":false,"internalType":"string"},{"name":"payload","type":"bytes","indexed":false,"internalType":"bytes"},{"name":"payload_hash","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"payload_signature","type":"bytes","indexed":false,"internalType":"bytes"},{"name":"user_key","type":"bytes","indexed":false,"internalType":"bytes"},{"name":"user_pubkey","type":"bytes","indexed":false,"internalType":"bytes"},{"name":"handle","type":"string","indexed":false,"internalType":"string"},{"name":"nonce","type":"bytes12","indexed":false,"internalType":"bytes12"}],"anonymous":false},{"type":"error","name":"CallbackError","inputs":[]},{"type":"error","name":"InvalidPacketSignature","inputs":[]},{"type":"error","name":"InvalidPayloadHash","inputs":[]},{"type":"error","name":"InvalidResultSignature","inputs":[]},{"type":"error","name":"InvalidSignature","inputs":[]},{"type":"error","name":"TaskAlreadyCompleted","inputs":[]}]
        const iface= new ethers.utils.Interface( abi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))
        
        const _callbackAddress = publicClientAddress;
        const _callbackSelector = iface.getSighash(iface.getFunction("callback"))
        const _callbackGasLimit = 300000

        const functionData = iface.encodeFunctionData("send",
            [
                _userAddress,
                _sourceNetwork,
                _routingInfo,
                _payloadHash,
                _info,
                _callbackAddress,
                _callbackSelector,
                _callbackGasLimit
            ]
        )

        const tx_params = [
            {
                gas: '0x0493E0', // 300000
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
        <p><b>Tx Hash: </b><a href="https://sepolia.etherscan.io/tx/${txHash}" target="_blank">${txHash}</a></p>
        <p><b>Gateway Address (to check the postExecution callback) </b><a href="https://sepolia.etherscan.io/address/${publicClientAddress}" target="_blank">${publicClientAddress}</a></p>
        <p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>
        `
    })
}