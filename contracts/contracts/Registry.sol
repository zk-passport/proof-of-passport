// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "hardhat/console.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract Registry is Ownable {

    bytes32 public merkleRoot;

    constructor(bytes32 _merkleRoot) {
        merkleRoot = _merkleRoot;
        transferOwnership(msg.sender);
    }

	function update(bytes32 _merkleRoot) public onlyOwner {
		merkleRoot = _merkleRoot;
	}

	function checkRoot(bytes32 _merkleRoot) public view returns (bool) {
		return merkleRoot == _merkleRoot;
	}
}