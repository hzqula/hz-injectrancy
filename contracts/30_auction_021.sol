// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/medium/auction_021.sol
pragma solidity ^0.8.0;

/**
 * @title ReverseAuction
 * @dev A vulnerable reverse auction with a 3-day bidding deadline and loose time check.
 * Template: Reverse Auction | Time Dependency: 3-day bidding deadline | Complexity: Medium
 */
contract ReverseAuction {
    address public immutable owner;
    uint256 public immutable auctionEndTime;
    address public lowestBidder;
    uint256 public lowestBid;
    bool public ended;
    bool public overridden;

    event AuctionEnded(address indexed winner, uint256 amount);
    event AuctionOverridden(address indexed winner, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor() {
        owner = msg.sender;
        auctionEndTime = block.timestamp + 3 days;
        lowestBid = type(uint256).max;
    }

    function placeBid(uint256 bidAmount) external {
        require(block.timestamp <= auctionEndTime, "Auction has ended"); // Vulnerable: <=
        require(!ended, "Auction already finalized");
        require(!overridden, "Auction overridden by owner");
        require(bidAmount < lowestBid, "Bid must be lower than current lowest");

        lowestBidder = msg.sender;
        lowestBid = bidAmount;

        emit AuctionEnded(msg.sender, bidAmount);
    }

    function endAuction() external {
        require(block.timestamp >= auctionEndTime, "Auction not yet ended");
        require(!ended, "Auction already ended");
        ended = true;
        emit AuctionEnded(lowestBidder, lowestBid);
    }

    function overrideWinner(address winner, uint256 amount) external onlyOwner {
        require(block.timestamp < auctionEndTime, "Cannot override after auction ends");
        require(!ended, "Auction already finalized");
        require(!overridden, "Already overridden");
        overridden = true;
        lowestBidder = winner;
        lowestBid = amount;
        emit AuctionOverridden(winner, amount);
    }
}