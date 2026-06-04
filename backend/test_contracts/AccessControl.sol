// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControl {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function setOwner(address newOwner) public {
        owner = newOwner;
    }

    function withdrawAll(address payable to) public {
        to.transfer(address(this).balance);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
