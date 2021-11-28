/**
 * Source Code first verified at https://etherscan.io on Tuesday, May 7, 2019
 (UTC) */

pragma solidity >=0.4.22 <0.6.0;



contract TokenERC20 {

    mapping (address => mapping (address => uint256)) public allowance;
    function burnFrom(address _from, uint256 _value) public returns (bool success) {
           // Check if the targeted balance is enough
        require(_value < allowance[_from][msg.sender]);    // Check allowance
                        // Subtract from the targeted balance
        allowance[_from][msg.sender] -= _value;  
        return true;
    }
}

