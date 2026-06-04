// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract UncheckedCall {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        msg.sender.call{value: amount}("");
    }

    function sendEther(address payable recipient, uint256 amount) public {
        recipient.send(amount);
    }
}
