// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Suicidal {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function kill() public {
        selfdestruct(payable(msg.sender));
    }

    function deposit() public payable {}
}
