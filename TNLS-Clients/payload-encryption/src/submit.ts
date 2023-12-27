//import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x6Df3Dbe48C8CE6DB408Cb44cc942cc05d7Dc48fB'
    const routing_info = "secret19x9zmnrdl98nrgc24cmt227qx5svskg6qkf9k6"
    const routing_code_hash = "288e2d7d77122540cefb1264002f101f0375e3dd77618668bee097ef0d2acf3f"

     //0x3309086633802E71fa00388cc0b86F809C910515
     const Resulthash = Buffer.from("923b23c023d0e5e66ac122d9804414f4f9cab06d7a6ce6c4b8c586a1fa57264c",'hex')
     console.log(Resulthash)
     const resultSignature = Buffer.from("2db95ebb82b81f8240d952e1c6edf021e098de63d32f1f0d3bbbb7daf0e9edbd3378fc42e31d1041467c76388a35078968f1f6f2eb781b5b83054a1d90ba41ff1c",'hex')
 
     const pubkey_result = recoverPublicKey(Resulthash, resultSignature)
     console.log(`Verify this matches the pubkey_result address: ${computeAddress(pubkey_result)}`)
 

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
         //const ciphertextHash = keccak256(Buffer.from(ciphertext))
         //const payloadHash = keccak256(Buffer.concat([Buffer.from("\x19Ethereum Signed Message:\n"),Buffer.from(`${ciphertext.length}`),ciphertext]))
         //const msgParams = ciphertextHash

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
                
        // create the abi interface and encode the function data
        const abi = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"CallbackError","type":"error"},{"inputs":[],"name":"InvalidPacketSignature","type":"error"},{"inputs":[],"name":"InvalidPayloadHash","type":"error"},{"inputs":[],"name":"InvalidResultSignature","type":"error"},{"inputs":[],"name":"InvalidSignature","type":"error"},{"inputs":[],"name":"InvalidSignatureLength","type":"error"},{"inputs":[],"name":"InvalidSignatureSValue","type":"error"},{"inputs":[],"name":"TaskAlreadyCompleted","type":"error"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"taskId","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"result","type":"bytes"}],"name":"ComputedResult","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"task_id","type":"uint256"},{"indexed":false,"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"indexed":false,"internalType":"bytes32","name":"result_hash","type":"bytes32"}],"name":"logCompletedTask","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"task_id","type":"uint256"},{"indexed":false,"internalType":"string","name":"source_network","type":"string"},{"indexed":false,"internalType":"address","name":"user_address","type":"address"},{"indexed":false,"internalType":"string","name":"routing_info","type":"string"},{"indexed":false,"internalType":"string","name":"routing_code_hash","type":"string"},{"indexed":false,"internalType":"bytes","name":"payload","type":"bytes"},{"indexed":false,"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"indexed":false,"internalType":"bytes","name":"payload_signature","type":"bytes"},{"indexed":false,"internalType":"bytes","name":"user_key","type":"bytes"},{"indexed":false,"internalType":"bytes","name":"user_pubkey","type":"bytes"},{"indexed":false,"internalType":"string","name":"handle","type":"string"},{"indexed":false,"internalType":"bytes12","name":"nonce","type":"bytes12"}],"name":"logNewTask","type":"event"},{"inputs":[{"internalType":"uint256","name":"_taskId","type":"uint256"},{"internalType":"bytes","name":"_result","type":"bytes"}],"name":"callback","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_masterVerificationAddress","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"masterVerificationAddress","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_taskId","type":"uint256"},{"internalType":"string","name":"_sourceNetwork","type":"string"},{"components":[{"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"internalType":"bytes","name":"result","type":"bytes"},{"internalType":"bytes32","name":"result_hash","type":"bytes32"},{"internalType":"bytes","name":"result_signature","type":"bytes"},{"internalType":"bytes32","name":"packet_hash","type":"bytes32"},{"internalType":"bytes","name":"packet_signature","type":"bytes"}],"internalType":"struct Gateway.PostExecutionInfo","name":"_info","type":"tuple"}],"name":"postExecution","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"","type":"string"}],"name":"route","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_userAddress","type":"address"},{"internalType":"string","name":"_sourceNetwork","type":"string"},{"internalType":"string","name":"_routingInfo","type":"string"},{"internalType":"bytes32","name":"_payloadHash","type":"bytes32"},{"components":[{"internalType":"bytes","name":"user_key","type":"bytes"},{"internalType":"bytes","name":"user_pubkey","type":"bytes"},{"internalType":"string","name":"routing_code_hash","type":"string"},{"internalType":"string","name":"handle","type":"string"},{"internalType":"bytes12","name":"nonce","type":"bytes12"},{"internalType":"bytes","name":"payload","type":"bytes"},{"internalType":"bytes","name":"payload_signature","type":"bytes"}],"internalType":"struct Gateway.ExecutionInfo","name":"_info","type":"tuple"},{"internalType":"address","name":"_callbackAddress","type":"address"},{"internalType":"bytes4","name":"_callbackSelector","type":"bytes4"},{"internalType":"uint32","name":"_callbackGasLimit","type":"uint32"}],"name":"send","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"","type":"uint256"}],"name":"tasks","outputs":[{"internalType":"bytes32","name":"payload_hash","type":"bytes32"},{"internalType":"address","name":"callback_address","type":"address"},{"internalType":"bytes4","name":"callback_selector","type":"bytes4"},{"internalType":"uint32","name":"callback_gas_limit","type":"uint32"},{"internalType":"bool","name":"completed","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"string","name":"_route","type":"string"},{"internalType":"address","name":"_verificationAddress","type":"address"},{"internalType":"bytes","name":"_signature","type":"bytes"}],"name":"updateRoute","outputs":[],"stateMutability":"nonpayable","type":"function"}]
        const iface= new ethers.utils.Interface( abi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))
        
        const _callbackAddress = publicClientAddress;
        const _callbackSelector = iface.getSighash(iface.getFunction("callback"))
        const _callbackGasLimit = 300000

        console.log(`_userAddress: ${_userAddress}
        _sourceNetwork: ${_sourceNetwork} 
        _routingInfo: ${_routingInfo} 
        _payloadHash: ${_payloadHash} 
        _info: ${JSON.stringify(_info)}
        _callbackAddress: ${_callbackAddress},
        _callbackSelector: ${_callbackSelector} ,
        _callbackGasLimit: ${_callbackGasLimit}`)

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