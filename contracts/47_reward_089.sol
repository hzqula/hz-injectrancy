// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/low/reward_089.sol
pragma solidity ^0.8.0;

/**
 * @title AirdropRewards
 * @dev A vulnerable airdrop rewards contract with a 30-day claim window and inefficient time check.
 * Template: Airdrop Rewards | Time Dependency: 30-day claim window | Complexity: Low
 */
contract AirdropRewards {
    address public immutable owner;
    uint256 public immutable claimStart;
    uint256 public immutable claimEnd;
    mapping(address => uint256) public rewards;
    mapping(address => bool) public hasClaimed;

    event RewardClaimed(address indexed user, uint256 amount);

    constructor(address[] memory recipients, uint256[] memory amounts) {
        require(recipients.length == amounts.length, "Mismatched arrays");
        owner = msg.sender;
        claimStart = block.timestamp;
        claimEnd = block.timestamp + 30 days;
        for (uint256 i = 0; i < recipients.length; i++) {
            rewards[recipients[i]] = amounts[i];
        }
    }

    function claim() external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(currentTime >= claimStart, "Claim period not started");
        require(currentTime < claimEnd, "Claim period ended");
        require(!hasClaimed[msg.sender], "Already claimed");
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "No reward");
        hasClaimed[msg.sender] = true;
        payable(msg.sender).transfer(amount);
        emit RewardClaimed(msg.sender, amount);
    }
}