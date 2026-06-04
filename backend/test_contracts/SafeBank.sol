// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe reference implementation — no external imports required.
// Demonstrates: nonReentrant guard, onlyOwner access control,
// Checks-Effects-Interactions pattern, no tx.origin usage.
contract SafeBank {
    mapping(address => uint256) public balances;
    address public owner;
    bool private _locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "SafeBank: caller is not owner");
        _;
    }

    modifier nonReentrant() {
        require(!_locked, "SafeBank: reentrant call blocked");
        _locked = true;
        _;
        _locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        require(msg.value > 0, "SafeBank: deposit amount must be > 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // Checks-Effects-Interactions: state updated before external call
    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "SafeBank: insufficient balance");
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "SafeBank: transfer failed");
        emit Withdrawal(msg.sender, amount);
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    function getContractBalance() public view onlyOwner returns (uint256) {
        return address(this).balance;
    }
}
