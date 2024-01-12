// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";
import "forge-std/Script.sol";
import {Gateway} from "../src/Gateway.sol";
import {RandomnessReciever} from "../src/RandomnessReciever.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";


contract DeployScript is Script {
    function setUp() public {}

    address deployer;
    ProxyAdmin proxyAdmin;
    Gateway gatewayLogic;
    TransparentUpgradeableProxy gatewayProxy;
    RandomnessReciever randomnessAddress;

    address verificationAddress = 0x5b5274c2ae6aA29B6e94048878a61814594D3409;

    uint256 privKey = vm.envUint("ETH_PRIVATE_KEY");


    /// @notice Get the encoded hash of the inputs for signing
    /// @param _routeInput Route name
    /// @param _verificationAddressInput Address corresponding to the route
    function getRouteHash(string memory _routeInput, address _verificationAddressInput) public pure returns (bytes32) {
        return keccak256(abi.encode(_routeInput, _verificationAddressInput));
    }

        /// @notice Hashes the encoded message hash
    /// @param _messageHash the message hash
    function getEthSignedMessageHash(bytes32 _messageHash) public pure returns (bytes32) {
        /*
        Signature is produced by signing a keccak256 hash with the following format:
        "\x19Ethereum Signed Message\n" + len(msg) + msg
        */
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash));
    }

    function run() public {
        deployer = vm.rememberKey(privKey);
        vm.startBroadcast();

        // Deploy ProxyAdmin
        proxyAdmin = new ProxyAdmin(msg.sender);

        // Deploy Gateway Logic Contract
        gatewayLogic = new Gateway();

        // Prepare initializer data for Gateway
        bytes memory initializerData = abi.encodeWithSelector(
            Gateway.initialize.selector
        );

        // Deploy TransparentUpgradeableProxy
        gatewayProxy = new TransparentUpgradeableProxy(
            address(gatewayLogic),
            address(proxyAdmin),
            initializerData
        );

        // Cast the proxy address to the Gateway interface
        Gateway gateway = Gateway(address(gatewayProxy));

        // Continue with your existing setup, but replace `gatewayAddress` with `gateway`
        randomnessAddress = new RandomnessReciever();
        console2.logAddress(address(gateway));
        console2.logAddress(deployer);

        randomnessAddress.setGatewayAddress(address(gateway));

        // Initialize master verification Address
        gateway.setMasterVerificationAddress(deployer); // Replace gatewayAddress with gateway
        /// ------ Update Routes Param Setup ------- ///

        string memory route = "secret-4";
        //address verificationAddress = vm.envAddress("SECRET_GATEWAY_ETH_ADDRESS");

        // Update the route with with masterVerificationKey signature
        bytes32 routeHash = getRouteHash(route, verificationAddress);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(routeHash);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, ethSignedMessageHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        gateway.updateRoute(route, verificationAddress, sig);

        vm.stopBroadcast();
    }
}