// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Secp256r1_new} from "../contracts/Secp256r1_new.sol";

contract Secp256r1Test is Test, Secp256r1_new {
    function testVerify(uint256 privateKey, bytes32 digest) public {
        // private key must be less than the secp256r1 curve order
        privateKey = bound(privateKey, 1, nn - 1);

        (uint256 x, uint256 y) = getPublicKey(privateKey);
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        assertTrue(Verify(x, y, uint256(r), uint256(s), digest));
    }
}