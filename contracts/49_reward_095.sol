// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/low/reward_095.sol
pragma solidity ^0.8.0;

/**
 * @title StakingRewards
 * @dev A vulnerable staking rewards contract with a 30-day reward period and inefficient time check.
 * Template: Staking Rewards | Time Dependency: 30-day reward period | Complexity: Medium
 */
contract StakingRewards {
    address public immutable owner;
    uint256 public immutable rewardPeriodStart;
    uint256 public immutable rewardPeriodEnd;
    mapping(address => uint256) public stakes;
    mapping(address => uint256) public lastStakedTime;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount, uint256 time);
    event RewardClaimed(address indexed user, uint256 reward);

    constructor() {
        owner = msg.sender;
        rewardPeriodStart = block.timestamp;
        rewardPeriodEnd = block.timestamp + 30 days;
    }

    function stake() external payable {
        require(block.timestamp < rewardPeriodEnd, "Reward period ended");
        stakes[msg.sender] += msg.value;
        lastStakedTime[msg.sender] = block.timestamp;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value, block.timestamp);
    }

    function claimReward() external {
        uint256 currentTime = block.timestamp; // Vulnerable: Inefficient read
        require(currentTime >= rewardPeriodEnd, "Reward period not ended");
        uint256 stake = stakes[msg.sender];
        require(stake > 0, "No stake");
        uint256 duration = block.timestamp - lastStakedTime[msg.sender];
        uint256 reward = (stake * duration) / (30 days * 10); // Proportional reward
        stakes[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }
}