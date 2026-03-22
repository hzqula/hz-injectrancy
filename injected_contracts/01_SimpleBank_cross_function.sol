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


    // [BUG-INJECTED] Cross-Function Reentrancy
    // Pola: Dua fungsi berbagi state yang belum konsisten
    // Fungsi pertama: withdraw tanpa update state
    function bug_reentrancy_cross_withdraw(uint256 _amount) public {
        require(balances[msg.sender] >= _amount, "Saldo tidak cukup");
        // BUG: state balances belum dikurangi, bisa dieksploitasi oleh
        // fungsi lain (bug_reentrancy_cross_getBalance) yang membaca state ini
        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer gagal");
        balances[msg.sender] -= _amount;
        totalDeposits -= _amount;
    }

    // Fungsi kedua: membaca state yang mungkin belum konsisten
    function bug_reentrancy_cross_getBalance() public view returns (uint256) {
        // BUG: state bisa dibaca saat cross-function reentrancy terjadi
        return balances[msg.sender];
    }

}