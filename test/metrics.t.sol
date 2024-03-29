// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

import {Secp256r1_itsobvioustech, PassKeyId} from "../contracts/vendor/Secp256r1_itsobvioustech.sol";
import {Secp256r1_maxrobot} from "../contracts/vendor/Secp256r1_maxrobot.sol";
import {FCL_ecdsa} from "../contracts/vendor/FCL_ecdsa.sol";
import {P256} from "../contracts/P256.sol";

contract Secp256r1ItsobvioustechImpl {
    function verify(uint256 x, uint256 y, bytes32 r, bytes32 s, bytes32 e) public view returns (bool) {
        return Secp256r1_itsobvioustech.Verify(PassKeyId(x, y, ""), uint256(r), uint256(s), uint256(e));
    }
}

contract Secp256r1MaxrobotImpl {
    function verify(uint256 x, uint256 y, bytes32 r, bytes32 s, bytes32 e) public pure returns (bool) {
        return Secp256r1_maxrobot.Verify(x, y, [uint256(r), uint256(s)], uint256(e));
    }
}

contract FCLImpl {
    function verify(uint256 x, uint256 y, bytes32 r, bytes32 s, bytes32 e) public view returns (bool) {
        return FCL_ecdsa.ecdsa_verify(e, uint256(r), uint256(s), x, y);
    }

    function recovery(bytes32 r, bytes32 s, uint8 v, bytes32 e) public view returns (address) {
        return FCL_ecdsa.ec_recover_r1(uint256(e), 27 + v, uint256(r), uint256(s));
    }
}

contract P256Impl {
    function verify(uint256 x, uint256 y, bytes32 r, bytes32 s, bytes32 e) public view returns (bool) {
        return P256.verify(x, y, uint256(r), uint256(s), uint256(e));
    }

    function recovery(bytes32 r, bytes32 s, uint8 v, bytes32 e) public view returns (uint256, uint256) {
        return P256.recovery(uint256(r), uint256(s), v, uint256(e));
    }

    function recoveryAddress(bytes32 r, bytes32 s, uint8 v, bytes32 e) public view returns (address) {
        return P256.recoveryAddress(uint256(r), uint256(s), v, uint256(e));
    }
}

contract P256Test is Test {
    uint256 constant COUNT = 100;

    Secp256r1ItsobvioustechImpl immutable secp256r1itsobvioustechimpl = new Secp256r1ItsobvioustechImpl();
    Secp256r1MaxrobotImpl       immutable secp256r1maxrobotimpl       = new Secp256r1MaxrobotImpl();
    FCLImpl                     immutable fclimpl                     = new FCLImpl();
    P256Impl                    immutable p256impl                    = new P256Impl();

    function testGas() public {
        for (uint256 i = 0; i < COUNT; ++i) {
            _run(
                _pk(keccak256(abi.encode(block.prevrandao, i, 0))),
                keccak256(abi.encode(block.prevrandao, i, 1))
            );
        }
    }

    function _pk(bytes32 seed) private pure returns (uint256) {
        // private key must be less than the secp256r1 curve order
        return bound(uint256(keccak256(abi.encode(seed))), 0, P256.nn - 1);
    }

    function _run(uint256 privateKey, bytes32 digest) public {
        (uint256 Qx, uint256 Qy) = P256.getPublicKey(privateKey);
        address Qa = P256.getAddress(Qx, Qy);
        (bytes32 r, bytes32 s) = vm.signP256(privateKey, digest);

        // Check itsobvioustech
        {
            assertTrue(secp256r1itsobvioustechimpl.verify(Qx, Qy, r, s, digest));
        }
        // Check maxrobot
        {
            assertTrue(secp256r1maxrobotimpl.verify(Qx, Qy, r, s, digest));
        }
        // Check FCL
        {
            assertTrue(fclimpl.verify(Qx, Qy, r, s, digest));
        }
        {
            address Qa0 = fclimpl.recovery(r, s, 0, digest);
            address Qa1 = fclimpl.recovery(r, s, 1, digest);
            assertTrue(Qa == Qa0 || Qa == Qa1);
        }
        // Check P256
        {
            assertTrue(p256impl.verify(Qx, Qy, r, s, digest));
        }
        {
            (uint256 Qx0, uint256 Qy0) = p256impl.recovery(r, s, 0, digest);
            (uint256 Qx1, uint256 Qy1) = p256impl.recovery(r, s, 1, digest);
            assertTrue((Qx0 == Qx && Qy0 == Qy) || (Qx1 == Qx && Qy1 == Qy));
        }
        {
            address Qa0 = p256impl.recoveryAddress(r, s, 0, digest);
            address Qa1 = p256impl.recoveryAddress(r, s, 1, digest);
            assertTrue(Qa == Qa0 || Qa == Qa1);
        }
    }
}