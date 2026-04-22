// SPDX-License-Identifier: MIT
// src -> https://github.com/imranpollob/smart-contract-vulnerability-dataset/blob/master/smart_contract_dataset/auctions/vulnerable/medium/auction_015.sol
pragma solidity ^0.8.0;

/**
 * @title DutchAuction
 * @dev A vulnerable Dutch auction with a 10-day price decrease and loose time check.
 * Template: Dutch Auction | Time Dependency: 10-day price decrease | Complexity: Medium
 */
contract DutchAuction {
    address public immutable owner;
    uint256 public immutable startPrice;
    uint256 public immutable auctionStartTime;
    uint256 public immutable auctionEndTime;
    address public buyer;
    bool public ended;
    bool public cancelled;

    event AuctionEnded(address indexed buyer, uint256 finalPrice);
    event AuctionCancelled();

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this");
        _;
    }

    constructor(uint256 _startPrice) {
        owner = msg.sender;
        startPrice = _startPrice;
        auctionStartTime = block.timestamp;
        auctionEndTime = block.timestamp + 10 days;
    }

    function getCurrentPrice() public view returns (uint256) {
        if (block.timestamp >= auctionEndTime || cancelled) return 0;
        uint256 elapsed = block.timestamp - auctionStartTime;
        uint256 priceDecrease = (startPrice * elapsed) / (10 days);
        return startPrice - priceDecrease;
    }

    function buy() external payable {
        require(!cancelled, "Auction is cancelled");
        require(block.timestamp <= auctionEndTime, "Auction has ended"); // Vulnerable: <=
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

    function cancelAuction() external onlyOwner {
        require(!ended, "Auction already finalized");
        cancelled = true;
        emit AuctionCancelled();
    }
}