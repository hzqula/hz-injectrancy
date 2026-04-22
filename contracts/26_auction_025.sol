// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/high/auction_025.sol
pragma solidity ^0.8.0;

/**
 * @title DutchAuction
 * @dev A vulnerable Dutch auction with a 3-day price decrease and adjustable end time.
 * Template: Dutch Auction | Time Dependency: 3-day price decrease | Complexity: Medium
 */
contract DutchAuction {
    address public immutable owner;
    uint256 public immutable startPrice;
    uint256 public auctionStartTime;
    uint256 public auctionEndTime;
    address public buyer;
    bool public ended;

    event AuctionEnded(address indexed buyer, uint256 finalPrice);
    event AuctionExtended(uint256 newEndTime);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor(uint256 _startPrice) {
        owner = msg.sender;
        startPrice = _startPrice;
        auctionStartTime = block.timestamp;
        auctionEndTime = block.timestamp + 3 days;
    }

    function getCurrentPrice() public view returns (uint256) {
        if (block.timestamp >= auctionEndTime) return 0;
        uint256 elapsed = block.timestamp - auctionStartTime;
        uint256 priceDecrease = (startPrice * elapsed) / (3 days);
        return startPrice - priceDecrease;
    }

    function buy() external payable {
        require(block.timestamp < auctionEndTime, "Auction has ended");
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

    function extendAuction(uint256 additionalDays) external onlyOwner {
        require(!ended, "Auction already finalized");
        auctionEndTime += additionalDays * 1 days; // Vulnerable: Adjustable end time
        emit AuctionExtended(auctionEndTime);
    }
}