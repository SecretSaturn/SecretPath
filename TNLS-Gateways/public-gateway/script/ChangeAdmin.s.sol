// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.25;

import "forge-std/Vm.sol";
import "forge-std/Script.sol";
import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";


contract ChangeAdmin is Script {
    function setUp() public {}

    ProxyAdmin gatewayProxyAdmin;

    function run() public {
        vm.startBroadcast();

        // Initialize the ProxyAdmin
        gatewayProxyAdmin = ProxyAdmin(0xb352D4449dC7355d4478784027d7AfAe69843085);

        // Get the current owner of the ProxyAdmin
        address currentOwner = gatewayProxyAdmin.owner();
        console.log("Current ProxyAdmin owner:", currentOwner);

        // Set the new owner of the ProxyAdmin
        address newProxyAdmin = 0xf80acFEC31073b08966b5b4E3968CCA498F62075;

        // Transfer ownership
        gatewayProxyAdmin.transferOwnership(newProxyAdmin);

        // Get the new owner of the ProxyAdmin
        address newOwner = gatewayProxyAdmin.owner();
        console.log("New ProxyAdmin owner:", newOwner);

        vm.stopBroadcast();
    }
}