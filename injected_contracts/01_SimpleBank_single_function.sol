// SPDX-License-Identifier: MIT
// src: https://gist.github.com/CodeWithJoe2020/9c140df7c13453fd690d28614c18d0c9

pragma solidity >=0.8.0;

contract SimpleBank {
    uint256 public totalDeposits;

    uint public transactions;
    mapping(address=>uint) balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value; // [TRACKER]
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

    // [ORACLE] Echidna property: saldo kontrak harus >= totalDeposits
    // Pelanggaran invariant ini menandakan aktivasi kerentanan reentrancy
    function echidna_cek_saldo() public view returns (bool) {
        return address(this).balance >= totalDeposits;
    }


    // [INJECTED] Receive function untuk mendukung pengiriman ether
    receive() external payable {
        totalDeposits += msg.value;
    }


    // [BUG-INJECTED] Single-Function Reentrancy
    // Pola: CEI (Check-Effects-Interactions) dilanggar
    // Transfer dilakukan SEBELUM state diperbarui
    function bug_reentrancy_single(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Saldo tidak cukup");
        // BUG: external call sebelum state update (pelanggaran CEI)
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer gagal");
        // State seharusnya diperbarui SEBELUM external call
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
    }

}