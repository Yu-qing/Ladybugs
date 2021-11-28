// SPDX-License-Identifier: MIT

pragma solidity >=0.6.0 <0.8.0;

import "./InblocksPrecedenceSynchronizer.sol";

contract InblocksPrecedenceSynchronizerDev is InblocksPrecedenceSynchronizer {

    event Reset();

    function reset() public onlyOwner {
        count = 0;
        emit Reset();
    }

}
