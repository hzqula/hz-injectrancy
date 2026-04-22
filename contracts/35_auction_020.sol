// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/low/auction_020.sol
pragma solidity ^0.8.0;

/**
 * @title ReverseAuction
 * @dev A vulnerable reverse auction with a 6-day bidding deadline and inefficient time check.
 * Template: Reverse Auction | Time Dependency: 6-day bidding deadline | Complexity: Low
 */
contract ReverseAuction {
    address public immutable owner;
    uint256 public immutable auctionEndTime;
    address public lowestBidder;
    uint256 public lowestBid;
    bool public ended;

    event AuctionEnded(address indexed winner, uint256 amount);

    constructor() {
        owner = msg.sender;
        auctionEndTime = block.timestamp + 6 days;
        lowestBid = type(uint256).max;
    }

    function placeBid(uint256 bidAmount) external {
        uint256 currentTime = block.timestamp; // Inefficient read
        require(currentTime < auctionEndTime, "Auction has ended");
        require(!ended, "Auction already finalized");
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
}