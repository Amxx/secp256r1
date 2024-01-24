// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// From https://github.com/OpenZeppelin/openzeppelin-contracts
library Math {
    /**
     * @dev Calculate the modular multiplicative inverse of a number in Z/nZ.
     *
     * If n is a prime, then Z/nZ is a field. In that case all elements are inversible, expect 0.
     * If n is not a prime, then Z/nZ is not a field, and some elements might not be inversible.
     *
     * If the input value is not inversible, 0 is returned.
     */
    function invMod(uint256 a, uint256 n) internal pure returns (uint256) {
        unchecked {
            if (n == 0) return 0;

            // The inverse modulo is calculated using the Extended Euclidean Algorithm (iterative version)
            // Used to compute integers x and y such that: ax + ny = gcd(a, n).
            // When the gcd is 1, then the inverse of a modulo n exists and it's x.
            // ax + ny = 1
            // ax = 1 + (-y)n
            // ax ≡ 1 (mod n) # x is the inverse of a modulo n

            // If the remainder is 0 the gcd is n right away.
            uint256 remainder = a % n;
            uint256 gcd = n;

            // Therefore the initial coefficients are:
            // ax + ny = gcd(a, n) = n
            // 0a + 1n = n
            int256 x = 0;
            int256 y = 1;

            while (remainder != 0) {
                uint256 quotient = gcd / remainder;

                (gcd, remainder) = (
                    // The old remainder is the next gcd to try.
                    remainder,
                    // Compute the next remainder.
                    // Can't overflow given that (a % gcd) * (gcd // (a % gcd)) <= gcd
                    // where gcd is at most n (capped to type(uint256).max)
                    gcd - remainder * quotient
                );

                (x, y) = (
                    // Increment the coefficient of a.
                    y,
                    // Decrement the coefficient of n.
                    // Can overflow, but the result is casted to uint256 so that the
                    // next value of y is "wrapped around" to a value between 0 and n - 1.
                    x - y * int256(quotient)
                );
            }

            if (gcd != 1) return 0; // No inverse exists.
            return x < 0 ? (n - uint256(-x)) : uint256(x); // Wrap the result if it's negative.
        }
    }
}

/**
 * @dev Implementation of secp256r1 verification.
 * Inspired by https://github.com/maxrobot/elliptic-solidity/blob/master/contracts/Secp256r1.sol
 * and optimized for solidity ^0.8.0.
 */
contract Secp256r1_new {
    uint256 public constant gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 public constant gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    uint256 public constant pp = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 public constant nn = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 public constant a  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 public constant b  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 public constant ss = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function getPublicKey(uint256 privateKey) public pure returns (uint256, uint256) {
        return ScalarMult(gx, gy, privateKey);
    }

    /**
     * @dev signature verification
     * @param X - public key coordinate X
     * @param Y - public key coordinate Y
     * @param R - signature half R
     * @param S - signature half S
     * @param digest - hashed message
     */
    function Verify(uint256 X, uint256 Y, uint256 R, uint256 S, bytes32 digest) public pure returns (bool) {
        if (R >= nn || S >= nn) return false;
        // if (R >= nn || S >= ss) return false; // TODO: find out why this causes issues

        uint256 e = uint256(digest);
        uint256 w = Math.invMod(S, nn);
        uint256 u1 = mulmod(e, w, nn);
        uint256 u2 = mulmod(R, w, nn);
        (uint256 x1, uint256 y1) = ScalarMult(gx, gy, u1);
        (uint256 x2, uint256 y2) = ScalarMult(X, Y, u2);
        (uint256 x, ) = Add(x1, y1, x2, y2);

        return (x % pp == R);
    }

    function Add(uint256 p1, uint256 p2, uint256 q1, uint256 q2) public pure returns(uint256, uint256) {
        uint256 p3;
        (p1, p2, p3) = _jAdd(p1, p2, uint256(1), q1, q2, uint256(1));
        return _affineFromJacobian(p1, p2, p3);
    }

    function Double(uint256 p1, uint256 p2) public pure returns(uint256, uint256) {
        uint256 p3;
        (p1, p2, p3) = _jDouble(p1, p2, uint256(1));
        return _affineFromJacobian(p1, p2, p3);
    }

    function ScalarMult(uint256 Bx, uint256 By, uint256 k) public pure returns (uint256, uint256) {
        uint256 x = 0;
        uint256 y = 0;
        uint256 z = 0;

        for (uint256 i = 0; i < 256; ++i) {
            (x, y, z) = _jDouble(x, y, z);
            if ((k >> (255 - i)) & 0x1 == 0x1) {
                (x, y, z) = _jAdd(Bx, By, 1, x, y, z);
            }
        }

        return _affineFromJacobian(x, y, z);
    }

    /**
        * @dev translate jacobian to affine coordinates
        */
    function _affineFromJacobian(uint256 x, uint256 y, uint256 z) public pure returns(uint256 ax, uint256 ay) {
        if (z == 0) return (0, 0);
        uint256 zinv = Math.invMod(z, pp);
        uint256 zinvsq = mulmod(zinv, zinv, pp);
        uint256 zinvcb = mulmod(zinvsq, zinv, pp);
        ax = mulmod(x, zinvsq, pp);
        ay = mulmod(y, zinvcb, pp);
    }

    /**
        * @dev add two Jacobian points as described in:
        * https://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/doubling/mdbl-2007-bl.op3
        */
    function _jAdd(uint256 p1, uint256 p2, uint256 p3, uint256 q1, uint256 q2, uint256 q3) public pure returns(uint256 r1, uint256 r2, uint256 r3) {
        if (p3 == 0) {
            return (q1, q2, q3);
        }
        if (q3 == 0) {
            return (p1, p2, p3);
        }
        assembly {
            let pd := pp
            let z1z1 := mulmod(p3, p3, pd) // Z1Z1 = Z1^2
            let z2z2 := mulmod(q3, q3, pd) // Z2Z2 = Z2^2

            let u1 := mulmod(p1, z2z2, pd) // U1 = X1*Z2Z2
            let u2 := mulmod(q1, z1z1, pd) // U2 = X2*Z1Z1

            let s1 := mulmod(p2, mulmod(z2z2, q3, pd), pd) // S1 = Y1*Z2*Z2Z2
            let s2 := mulmod(q2, mulmod(z1z1, p3, pd), pd) // S2 = Y2*Z1*Z1Z1

            mstore(0x02A0, addmod(p3, q3, pd))

            if lt(u2, u1) {
                u2 := add(pd, u2) // u2 = u2+pd
            }
            let h := sub(u2, u1) // H = U2-U1

            let i := mulmod(mulmod(0x02, h, pd), mulmod(0x02, h, pd), pd) // I = (2*H)^2

            let j := mulmod(h, i, pd) // J = H*I
            if lt(s2, s1) {
                s2 := add(pd, s2) // u2 = u2+pd
            }
            let rr := mulmod(0x02, sub(s2, s1), pd) // r = 2*(S2-S1)

            let v := mulmod(u1, i, pd) // V = U1*I
            r1 := mulmod(rr, rr, pd) // X3 = R^2

            mstore(0x0260, addmod(j, mulmod(0x02, v, pd), pd)) // I = J+(2*V)
            if lt(r1, mload(0x0260)) {
                r1 := add(pd, r1) // X3 = X3+pd
            }
            r1 := sub(r1, mload(0x0260))

            // Y3 = r*(V-X3)-2*S1*J
            mstore(0x0220, mulmod(0x02, s1, pd))
            mstore(0x0220, mulmod(mload(0x0220), j, pd))

            if lt(v, r1) {
                v := add(pd, v)
            }
            mstore(0x0240, sub(v, r1))
            mstore(0x0240, mulmod(rr, mload(0x240), pd))

            if lt(mload(0x0240), mload(0x0220)) {
                mstore(0x0240, add(mload(0x0240), pd))
            }
            mstore(0x0240, sub(mload(0x0240), mload(0x0220)))
            r2 := mload(0x0240)

            // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
            z1z1 := addmod(z1z1, z2z2, pd)
            mstore(0x0260, mulmod(mload(0x02A0), mload(0x02A0), pd))
            // r3 := mload(0x0260)
            if lt(mload(0x0260), z1z1) {
                mstore(0x0260, add(pd, mload(0x0260)))
            }
            r3 := mulmod(sub(mload(0x0260), z1z1), h, pd)
        }
        return (r1, r2, r3);
    }

    /**
        * @dev double a Jacobian point as described in:
        * https://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/doubling/dbl-2001-b.op3
        */
    function _jDouble(uint256 p1, uint256 p2, uint256 p3) public pure returns(uint256 q1, uint256 q2, uint256 q3) {
        assembly {
        let pd := 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
        let delta := mulmod(p3, p3, pd) // delta = Z1^2
        let gamma := mulmod(p2, p2, pd) // gamma = Y1^2
        let beta := mulmod(p1, gamma, pd) // beta = X1*gamma

        let alpha := p1
        if lt(alpha, delta) {
            alpha := add(pd, alpha)
        }
        alpha := mulmod(0x03 , mulmod(sub(alpha, delta), addmod(p1, delta, pd), pd), pd) // alpha = 3*(X1-delta)*(X1+delta)

        q1 := mulmod(alpha, alpha, pd)
        if lt(q1, mulmod(0x08, beta, pd)) {
            q1 := add(pd, q1)
        }
        q1 := sub(q1, mulmod(0x08, beta, pd)) // X3 = (alpha^2)-(8*beta)

        q3  := addmod(p2, p3, pd)
        q3 := mulmod(q3, q3, pd)

        delta := addmod(delta, gamma, pd)
        if lt(q3, delta) {
            q3 := add(pd, q3)
        }
        q3 := sub(q3, delta) // Z3 = (Y1+Z1)^2-gamma-delta

        q2 := mulmod(0x04, beta, pd)
        if lt(q2, q1) {
            q2 := add(pd, q2)
        }
        q2 := mulmod(alpha, sub(q2, q1), pd)
        gamma := mulmod(0x08, mulmod(gamma, gamma, pd), pd)
        if lt(q2, gamma) {
            q2 := add(pd, q2)
        }
        q2 := sub(q2, gamma) // Y3 = alpha*(4*beta-X3)-8*gamma^2
        }
    }
}
