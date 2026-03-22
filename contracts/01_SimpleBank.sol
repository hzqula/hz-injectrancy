// SPDX-License-Identifier: MIT
// src: https://gist.github.com/CodeWithJoe2020/9c140df7c13453fd690d28614c18d0c9

pragma solidity >=0.8.0;

contract SimpleBank {
    uint public transactions;
    mapping(address=>uint) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        transactions++;
    }

    function getBalance() public view returns (uint) {
        return balances[msg.sender];
    }

    function withdraw(uint amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        transactions++;
    }

    function getTotalBalance() public view returns(uint){
        return address(this).balance;
    }
}