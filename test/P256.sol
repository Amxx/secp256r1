// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {P256} from "../contracts/P256.sol";

contract P256Test is Test {
    function testVerify(uint256 privateKey, bytes32 digest) public {
        // private key must be less than the secp256r1 curve order
        privateKey = bound(privateKey, 1, P256.nn - 1);

        // digest must not be 0 ?
        vm.assume(digest != 0);

        (uint256 x, uint256 y) = P256.getPublicKey(privateKey);
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);
        assertTrue(P256.verify(x, y, uint256(r), uint256(s), digest));
    }
}