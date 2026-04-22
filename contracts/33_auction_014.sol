// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/low/auction_014.sol
pragma solidity ^0.8.0;

/**
 * @title DutchAuction
 * @dev A vulnerable Dutch auction with a 5-day price decrease and redundant time read.
 * Template: Dutch Auction | Time Dependency: 5-day price decrease | Complexity: Low
 */
contract DutchAuction {
    address public immutable owner;
    uint256 public immutable startPrice;
    uint256 public immutable auctionStartTime;
    uint256 public immutable auctionEndTime;
    address public buyer;
    bool public ended;

    event AuctionEnded(address indexed buyer, uint256 finalPrice);

    constructor(uint256 _startPrice) {
        owner = msg.sender;
        startPrice = _startPrice;
        auctionStartTime = block.timestamp;
        auctionEndTime = block.timestamp + 5 days;
    }

    function getCurrentPrice() public view returns (uint256) {
        if (block.timestamp >= auctionEndTime) return 0;
        uint256 elapsed = block.timestamp - auctionStartTime;
        uint256 priceDecrease = (startPrice * elapsed) / (5 days);
        return startPrice - priceDecrease;
    }

    function buy() external payable {
        uint256 currentTime = block.timestamp; // Inefficient read
        require(currentTime < auctionEndTime, "Auction has ended");
        require(!ended, "Auction already finalized");
        uint256 currentPrice = getCurrentPrice();
        require(msg.value >= currentPrice, "Insufficient payment");
        require(buyer == address(0), "Item already sold");

        buyer = msg.sender;
        ended = true;

        if (msg.value > currentPrice) {
            payable(msg.sender).transfer(msg.value - currentPrice);
        }
        payable(owner).transfer(currentPrice);

        emit AuctionEnded(buyer, currentPrice);
    }
}