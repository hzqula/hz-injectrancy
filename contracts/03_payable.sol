// SPDX-License-Identifier: MIT
// src -> https://github.com/sweekar2999/Solidity/blob/main/payable.sol
pragma solidity ^0.8.13;

contract Bank {
    mapping(address => uint256) bal;

    // Make the constructor payable to allow receiving Ether during deployment
    constructor() payable {
        // Optionally, initialize the contract's balance if needed
        if (msg.value > 0) {
            bal[msg.sender] = msg.value;
        }
    }

    // Deposit function
    function depo() public payable {
        require(msg.value > 0, "Invalid amount");
        bal[msg.sender] += msg.value;
    }

    // Withdraw function
  function with(uint256 amt) public {
    require(amt <= bal[msg.sender], "Amount greater than balance"); // Check user balance
    bal[msg.sender] -= amt; // Deduct amount from user's balance in the contract
    payable(msg.sender).transfer(amt); // Transfer the amount to the user's account
}


    // Check the contract's total balance
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    // Check an individual’s balance in the contract
    function getBalance(address account) public view returns (uint256) {
        return bal[account];
    }
}