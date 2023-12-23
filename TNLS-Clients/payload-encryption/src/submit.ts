//import { encrypt_payload } from "./wasm";
import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer/";
import secureRandom from "secure-random";

export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x1E2d6bd7cE302DAe284373514c5Ca6826f6f214B'
    const routing_info = "secret16cv5wll9ed5dqww47g0u5grprpn0eertuzg3cu"
    const routing_code_hash = "12f9880e67d423742dd1009ae1764d1f113510baf427bdfae3ea2a5607a7c63a"

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
        //const cyphertextHash = keccak256(Buffer.from(ciphertext))
        //const payloadHash = keccak256(Buffer.from("\x19Ethereum Signed Message:\n" + "32" + cyphertextHash.substring(2)))
        const payloadHash = keccak256(Buffer.from("\x19Ethereum Signed Message:\n" + ciphertext.length + ciphertext))
        const msgParams = ciphertext.toString('ASCII')
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

        console.log(`_userAddress: ${_userAddress}
            _sourceNetwork: ${_sourceNetwork} 
            _routingInfo: ${_routingInfo} 
            _payloadHash: ${_payloadHash} 
            _info: ${JSON.stringify(_info)}`)
                
        // create the abi interface and encode the function data
        const abi = [{"inputs":[{"internalType":"address","name":"_gatewayAddress","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"uint256","name":"taskId","type":"uint256"},{"indexed":false,"internalType":"bytes","name":"result","type":"bytes"}],"name":"ComputedResult","type":"event"},{"inputs":[],"name":"GatewayAddress","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_taskId","type":"uint256"},{"internalType":"bytes","name":"_result","type":"bytes"}],"name":"callback","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_userAddress","type":"address"},{"internalType":"string","name":"_sourceNetwork","type":"string"},{"internalType":"string","name":"_routingInfo","type":"string"},{"internalType":"bytes32","name":"_payloadHash","type":"bytes32"},{"components":[{"internalType":"bytes","name":"user_key","type":"bytes"},{"internalType":"bytes","name":"user_pubkey","type":"bytes"},{"internalType":"string","name":"routing_code_hash","type":"string"},{"internalType":"string","name":"handle","type":"string"},{"internalType":"bytes12","name":"nonce","type":"bytes12"},{"internalType":"bytes","name":"payload","type":"bytes"},{"internalType":"bytes","name":"payload_signature","type":"bytes"}],"internalType":"struct Util.ExecutionInfo","name":"_info","type":"tuple"}],"name":"send","outputs":[],"stateMutability":"nonpayable","type":"function"}]
        const iface= new ethers.utils.Interface( abi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))
        const functionData = iface.encodeFunctionData("send",
            [
                _userAddress,
                _sourceNetwork,
                _routingInfo,
                _payloadHash,
                _info
            ]
        )

        const tx_params = [
            {
                nonce: '0x00', // ignored by MetaMask
                gasPrice: '0x3B9B1820', // 1000020000
                gas: '0x0493E0', // 300000
                to: publicClientAddress,
                from: myAddress,
                value: '0x00', // 0
                data: functionData, // TODO figure out what this data is meant to be
                chainId: "0x5"  // ignored by MetaMask
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