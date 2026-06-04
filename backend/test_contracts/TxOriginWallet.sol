// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TxOriginWallet {
    address public owner;

    constructor() {
        owner = tx.origin;
    }

    function transferTo(address payable _to, uint256 _amount) public {
        require(tx.origin == owner, "Not authorized");
        _to.transfer(_amount);
    }

    function deposit() public payable {}

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
