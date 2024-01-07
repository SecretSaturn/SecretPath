import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer";
import secureRandom from "secure-random";

export function setupSubmit(element: HTMLButtonElement) {

    const publicClientAddress = '0x62A76e4fFB2fa4b4FecA249cD1646C7fD1469319'
    const routing_contract = "secret1zash9uk88y3sr8sjf0jdrlfsdsyuk6szvj99k6"
    const routing_code_hash = "d94d2cd7d22f0509c7ca0b80d6576ecfebf2618c6026204c30a35f6624cb3230"

    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        const [myAddress] = await provider.send("eth_requestAccounts", []);

        const data = JSON.stringify({
            numWords:20
        })


        // create the abi interface and encode the function data
        const abi = [{"type":"constructor","inputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"callback","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_result","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"postExecution","inputs":[{"name":"_taskId","type":"uint256","internalType":"uint256"},{"name":"_sourceNetwork","type":"string","internalType":"string"},{"name":"_info","type":"tuple","internalType":"struct Gateway.PostExecutionInfo","components":[{"name":"payload_hash","type":"bytes32","internalType":"bytes32"},{"name":"result_hash","type":"bytes32","internalType":"bytes32"},{"name":"packet_hash","type":"bytes32","internalType":"bytes32"},{"name":"callback_address","type":"bytes20","internalType":"bytes20"},{"name":"callback_selector","type":"bytes4","internalType":"bytes4"},{"name":"callback_gas_limit","type":"bytes4","internalType":"bytes4"},{"name":"packet_signature","type":"bytes","internalType":"bytes"},{"name":"result_signature","type":"bytes","internalType":"bytes"},{"name":"result","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"requestRandomWords","inputs":[{"name":"_numWords","type":"uint32","internalType":"uint32"},{"name":"_callbackGasLimit","type":"uint32","internalType":"uint32"}],"outputs":[{"name":"requestId","type":"uint256","internalType":"uint256"}],"stateMutability":"payable"},{"type":"function","name":"send","inputs":[{"name":"_payloadHash","type":"bytes32","internalType":"bytes32"},{"name":"_userAddress","type":"address","internalType":"address"},{"name":"_routingInfo","type":"string","internalType":"string"},{"name":"_info","type":"tuple","internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setContractAddressAndCodeHash","inputs":[{"name":"_contractAddress","type":"string","internalType":"string"},{"name":"_contractCodeHash","type":"string","internalType":"string"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setMasterVerificationAddress","inputs":[{"name":"_masterVerificationAddress","type":"address","internalType":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"updateRoute","inputs":[{"name":"_route","type":"string","internalType":"string"},{"name":"_verificationAddress","type":"address","internalType":"address"},{"name":"_signature","type":"bytes","internalType":"bytes"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"ComputedResult","inputs":[{"name":"taskId","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"result","type":"bytes","indexed":false,"internalType":"bytes"}],"anonymous":false},{"type":"event","name":"logCompletedTask","inputs":[{"name":"task_id","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"payload_hash","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"result_hash","type":"bytes32","indexed":false,"internalType":"bytes32"}],"anonymous":false},{"type":"event","name":"logNewTask","inputs":[{"name":"task_id","type":"uint256","indexed":true,"internalType":"uint256"},{"name":"source_network","type":"string","indexed":false,"internalType":"string"},{"name":"user_address","type":"address","indexed":false,"internalType":"address"},{"name":"routing_info","type":"string","indexed":false,"internalType":"string"},{"name":"payload_hash","type":"bytes32","indexed":false,"internalType":"bytes32"},{"name":"info","type":"tuple","indexed":false,"internalType":"struct Gateway.ExecutionInfo","components":[{"name":"user_key","type":"bytes","internalType":"bytes"},{"name":"user_pubkey","type":"bytes","internalType":"bytes"},{"name":"routing_code_hash","type":"string","internalType":"string"},{"name":"handle","type":"string","internalType":"string"},{"name":"nonce","type":"bytes12","internalType":"bytes12"},{"name":"payload","type":"bytes","internalType":"bytes"},{"name":"payload_signature","type":"bytes","internalType":"bytes"}]}],"anonymous":false},{"type":"error","name":"CallbackError","inputs":[]},{"type":"error","name":"InvalidPacketSignature","inputs":[]},{"type":"error","name":"InvalidPayloadHash","inputs":[]},{"type":"error","name":"InvalidResultSignature","inputs":[]},{"type":"error","name":"InvalidSignature","inputs":[]},{"type":"error","name":"InvalidSignatureLength","inputs":[]},{"type":"error","name":"InvalidSignatureSValue","inputs":[]},{"type":"error","name":"TaskAlreadyCompleted","inputs":[]}]
        const iface= new ethers.utils.Interface( abi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))


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