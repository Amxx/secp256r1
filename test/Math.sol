// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Math} from "../contracts/Math.sol";

contract MathTest is Test {
    function testSqrt(uint256 value) public {
        value = bound(value, 0, P256.pp - 1);
        uint256 result = Math.sqrtMod(value, P256.pp);
        if (result > 0) {
            assertEq(mulmod(result, result, P256.pp), value);
        }
    }
}