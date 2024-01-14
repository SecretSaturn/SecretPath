import { ethers } from "ethers";
import { arrayify, hexlify, SigningKey, keccak256, recoverPublicKey, computeAddress, sha256 } from "ethers/lib/utils";
import { Buffer } from "buffer";
import secureRandom from "secure-random";

export async function setupSubmit(element: HTMLButtonElement) {

    const randomnessContract = '0x67AdB577bAAcce02D436CaaEE005630f57A3C4e5'

    // @ts-ignore
    const provider = new ethers.providers.Web3Provider(window.ethereum);

    // Create a contract instance
    const randomnessAbi = [{"type":"constructor","inputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"VRFGateway","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"fulfillRandomWords","inputs":[{"name":"requestId","type":"uint256","internalType":"uint256"},{"name":"randomWords","type":"uint256[]","internalType":"uint256[]"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"owner","inputs":[],"outputs":[{"name":"","type":"address","internalType":"address"}],"stateMutability":"view"},{"type":"function","name":"requestRandomnessTest","inputs":[],"outputs":[],"stateMutability":"nonpayable"},{"type":"function","name":"setGatewayAddress","inputs":[{"name":"_VRFGateway","type":"address","internalType":"address"}],"outputs":[],"stateMutability":"nonpayable"},{"type":"event","name":"fulfilledRandomWords","inputs":[{"name":"requestId","type":"uint256","indexed":false,"internalType":"uint256"},{"name":"randomWords","type":"uint256[]","indexed":false,"internalType":"uint256[]"}],"anonymous":false},{"type":"event","name":"requestRandomness","inputs":[{"name":"requestId","type":"uint256","indexed":false,"internalType":"uint256"}],"anonymous":false}]
    const randomnessContractInterface = new ethers.Contract(randomnessContract, randomnessAbi, provider);

    element.addEventListener("click", async function(event: Event){
        event.preventDefault()
        const [myAddress] = await provider.send("eth_requestAccounts", []);


        // create the abi interface and encode the function data
        const iface= new ethers.utils.Interface( randomnessAbi )
        const FormatTypes = ethers.utils.FormatTypes;
        console.log(iface.format(FormatTypes.full))


        const functionData = iface.encodeFunctionData("requestRandomnessTest")
        console.log(functionData)

        await window.ethereum.request({
            "method": "wallet_switchEthereumChain",
            "params": [
              {
                "chainId": "0xAA36A7"
              }
            ]
          });

        const tx_params = [
            {
                gas: '0x249F0', // 150000
                to: randomnessContract,
                from: myAddress,
                value: '0x00', // 0
                data: functionData, 
            },
          ];

        const txHash = await provider.send("eth_sendTransaction", tx_params);

        // Set up an event listener for the 'logNewTask' event
        randomnessContractInterface.on('requestRandomness', (originalRequestId) => {
            // This code is executed when the event is emitted
            console.log(`Request ID: ${originalRequestId}`);
            // Additional data from the event can be accessed if needed
            // You can also access other properties of the event object, like event.blockNumber
        // Set up an event listener for the 'fulfilledRandomWords' event
        randomnessContractInterface.on('fulfilledRandomWords', (requestId, randomWords, event) => {
            // This code is executed when the event is emitted
            if (originalRequestId == requestId) {
                console.log(`Request ID: ${requestId}`);
                console.log(`Random Words: ${randomWords}`);
                // You can access other event properties like event.blockNumber if needed
                document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `
        
                </p>
        
                <h2>Transaction Parameters</h2>
                <p><b>Request ID: ${requestId} </b></p>
                <p><b>Random Words: ${randomWords} </b></p>
                <p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>
                `
            }
        });
        });

        document.querySelector<HTMLDivElement>('#preview')!.innerHTML = `

        </p>

        <h2>Transaction Parameters</h2>
        <p><b>Tx Hash: </b><a href="https://sepolia.etherscan.io/tx/${txHash}" target="_blank">${txHash}</a></p>
        <p><b>Randomness Contract Address </b><a href="https://sepolia.etherscan.io/address/${randomnessContract}" target="_blank">${randomnessContract}</a></p>
        <p style="font-size: 0.8em;">${JSON.stringify(tx_params)}</p>
        `

    })
}