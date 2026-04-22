// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/reward_distribution/vulnerable/medium/reward_096.sol
pragma solidity ^0.8.0;

/**
 * @title StakingRewards
 * @dev A vulnerable staking rewards contract with a 10-day reward period and missing start check.
 * Template: Staking Rewards | Time Dependency: 10-day reward period | Complexity: Low
 */
contract StakingRewards {
    address public immutable owner;
    uint256 public immutable rewardPeriodStart;
    uint256 public immutable rewardPeriodEnd;
    mapping(address => uint256) public stakes;
    uint256 public totalStaked;

    event Staked(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 reward);

    constructor() {
        owner = msg.sender;
        rewardPeriodStart = block.timestamp;
        rewardPeriodEnd = block.timestamp + 10 days;
    }

    function stake() external payable {
        // Vulnerable: Missing block.timestamp >= rewardPeriodStart check
        require(block.timestamp < rewardPeriodEnd, "Reward period ended");
        stakes[msg.sender] += msg.value;
        totalStaked += msg.value;
        emit Staked(msg.sender, msg.value);
    }

    function claimReward() external {
        require(block.timestamp >= rewardPeriodEnd, "Reward period not ended");
        uint256 stake = stakes[msg.sender];
        require(stake > 0, "No stake");
        uint256 reward = (stake * 10) / 100; // 10% reward
        stakes[msg.sender] = 0;
        payable(msg.sender).transfer(reward);
        emit RewardClaimed(msg.sender, reward);
    }
}