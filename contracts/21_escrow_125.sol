// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/escrow_contracts/vulnerable/high/escrow_122.sol

pragma solidity ^0.8.0;

/**
 * @title PaymentEscrow
 * @dev A vulnerable payment escrow contract with a 21-day release timeout and adjustable timeout.
 * Template: Payment Escrow | Time Dependency: 21-day release timeout | Complexity: High
 */
contract PaymentEscrow {
    address public immutable payer;
    address public immutable payee;
    uint256 public releaseTime; // Vulnerable: Not immutable
    mapping(address => uint256) public deposits;
    uint256 public totalDeposited;
    bool public released;
    bool public paused;

    event Deposited(address indexed payer, uint256 amount);
    event Released(address indexed payee, uint256 amount);
    event Refunded(address indexed payer, uint256 amount);
    event TimeoutExtended(uint256 newReleaseTime);
    event Paused(bool paused);

    constructor(address _payee) {
        require(_payee != address(0), "Invalid payee");
        payer = msg.sender;
        payee = _payee;
        releaseTime = block.timestamp + 21 days;
    }

    function deposit() external payable {
        require(!paused, "Contract paused");
        require(msg.sender == payer, "Only payer can deposit");
        require(block.timestamp < releaseTime, "Release timeout passed");
        deposits[msg.sender] += msg.value;
        totalDeposited += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function release() external {
        require(!paused, "Contract paused");
        require(msg.sender == payee, "Only payee can release");
        require(block.timestamp >= releaseTime, "Release timeout not reached");
        require(!released, "Already released");
        released = true;
        payable(payee).transfer(totalDeposited);
        emit Released(payee, totalDeposited);
    }

    function refund() external {
        require(!paused, "Contract paused");
        require(msg.sender == payer, "Only payer can refund");
        require(block.timestamp < releaseTime, "Release timeout passed");
        require(!released, "Already released");
        released = true;
        payable(payer).transfer(totalDeposited);
        emit Refunded(payer, totalDeposited);
    }

    function extendTimeout(uint256 additionalDays) external {
        require(msg.sender == payer, "Only payer can extend");
        releaseTime += additionalDays * 1 days; // Vulnerable: Adjustable timeout
        emit TimeoutExtended(releaseTime);
    }

    function togglePause() external {
        require(msg.sender == payer, "Only payer can pause");
        paused = !paused;
        emit Paused(paused);
    }
}