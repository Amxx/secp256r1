// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import { Math } from "./Math.sol";

// Heavily inspired from
// https://github.com/maxrobot/elliptic-solidity/blob/master/contracts/Secp256r1.sol
// https://github.com/tdrerup/elliptic-curve-solidity/blob/master/contracts/curves/EllipticCurve.sol
// and modified jacobian double
// optimisations to avoid to an from from affine and jacobian coordinates
library P256 {
    struct JPoint {
        uint256 x;
        uint256 y;
        uint256 z;
    }

    uint256 constant gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
    uint256 constant gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;
    uint256 constant pp = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
    uint256 constant nn = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 constant a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 constant b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 constant MOST_SIGNIFICANT = 0xc000000000000000000000000000000000000000000000000000000000000000;

    /**
     * @dev signature verification
     * @param px - public key coordinate X
     * @param py - public key coordinate Y
     * @param r - signature half R
     * @param s - signature half S
     * @param e - hashed message
     */
    function verify(uint256 px, uint256 py, uint256 r, uint256 s, uint256 e) internal view returns (bool) {
        if (r >= nn || s >= nn) return false;

        JPoint[16] memory points = _preComputeJacobianPoints(px, py);
        uint256 w = _primemod(s, nn);
        uint256 u1 = mulmod(e, w, nn);
        uint256 u2 = mulmod(r, w, nn);
        (uint256 x, ) = _shamirMultJacobian(points, u1, u2);
        return (x == r);
    }

    /**
     * @dev public key recovery
     * @param r - signature half R
     * @param s - signature half S
     * @param v - signature recovery param
     * @param e - hashed message
     */
    function recovery(uint256 r, uint256 s, uint8 v, uint256 e) internal view returns (uint256, uint256) {
        if (r >= nn || s >= nn || v > 1) return (0, 0);

        uint256 rx = r;
        uint256 ry2 = addmod(mulmod(addmod(mulmod(rx, rx, pp), a, pp), rx, pp), b, pp); // weierstrass equation y² = x³ + a.x + b
        uint256 ry = Math.modExp(ry2, (pp + 1) / 4, pp); // This formula for sqrt work because pp ≡ 3 (mod 4)
        if (mulmod(ry, ry, pp) != ry2) return (0, 0);
        if (ry % 2 != v % 2) ry = pp - ry;

        JPoint[16] memory points = _preComputeJacobianPoints(rx, ry);
        uint256 w = _primemod(r, nn);
        uint256 u1 = mulmod(nn - (e % nn), w, nn);
        uint256 u2 = mulmod(s, w, nn);
        (uint256 x, uint256 y) = _shamirMultJacobian(points, u1, u2);
        return (x, y);
    }

    function getPublicKey(uint256 privateKey) internal view returns (uint256, uint256) {
        uint256 k = privateKey;
        uint256 x = 0;
        uint256 y = 0;
        uint256 z = 0;
        unchecked {
            for (uint256 i = 0; i < 256; ++i) {
                (x, y, z) = _jDouble(x, y, z);
                if ((k >> (255 - i)) & 0x1 == 0x1) {
                    (x, y, z) = _jAdd(gx, gy, 1, x, y, z);
                }
            }
        }
        return _affineFromJacobian(x, y, z);
    }

    /**
     * Strauss Shamir trick for EC multiplication
     * https://stackoverflow.com/questions/50993471/ec-scalar-multiplication-with-strauss-shamir-method
     * we optimise on this a bit to do with 2 bits at a time rather than a single bit
     * the individual points for a single pass are precomputed
     * overall this reduces the number of additions while keeping the same number of doublings
     */
    function _shamirMultJacobian(JPoint[16] memory points, uint256 u1, uint256 u2) private view returns (uint256, uint256) {
        uint256 x = 0;
        uint256 y = 0;
        uint256 z = 0;
        uint256 i = 0;
        uint256 bits = 128;
        unchecked {
            while (bits > 0) {
                if (z > 0) {
                    (x, y, z) = _jDouble(x, y, z);
                    (x, y, z) = _jDouble(x, y, z);
                }
                i = ((u1 & MOST_SIGNIFICANT) >> 252) | ((u2 & MOST_SIGNIFICANT) >> 254);
                if (i > 0) {
                    (x, y, z) = _jAdd(x, y, z, points[i].x, points[i].y, points[i].z);
                }
                u1 <<= 2;
                u2 <<= 2;
                --bits;
            }
        }
        return _affineFromJacobian(x, y, z);
    }

    function _preComputeJacobianPoints(uint256 px, uint256 py) private pure returns (JPoint[16] memory points) {
        points[0x00] = JPoint(0, 0, 0);
        points[0x01] = JPoint(px, py, 1);
        points[0x04] = JPoint(gx, gy, 1);
        points[0x02] = _jPointDouble(points[0x01]);
        points[0x08] = _jPointDouble(points[0x04]);
        points[0x03] = _jPointAdd(points[0x01], points[0x02]);
        points[0x05] = _jPointAdd(points[0x01], points[0x04]);
        points[0x06] = _jPointAdd(points[0x02], points[0x04]);
        points[0x07] = _jPointAdd(points[0x03], points[0x04]);
        points[0x09] = _jPointAdd(points[0x01], points[0x08]);
        points[0x0a] = _jPointAdd(points[0x02], points[0x08]);
        points[0x0b] = _jPointAdd(points[0x03], points[0x08]);
        points[0x0c] = _jPointAdd(points[0x04], points[0x08]);
        points[0x0d] = _jPointAdd(points[0x01], points[0x0c]);
        points[0x0e] = _jPointAdd(points[0x02], points[0x0c]);
        points[0x0f] = _jPointAdd(points[0x03], points[0x0C]);
    }

    function _jPointAdd(JPoint memory p1, JPoint memory p2) private pure returns (JPoint memory) {
        (uint256 x, uint256 y, uint256 z) = _jAdd(p1.x, p1.y, p1.z, p2.x, p2.y, p2.z);
        return JPoint(x, y, z);
    }

    function _jPointDouble(JPoint memory p) private pure returns (JPoint memory) {
        (uint256 x, uint256 y, uint256 z) = _jDouble(p.x, p.y, p.z);
        return JPoint(x, y, z);
    }

    /**
     * @dev returns affine coordinates from a jacobian input follows golang elliptic/crypto library
     */
    function _affineFromJacobian(uint256 x, uint256 y, uint256 z) private view returns (uint256 ax, uint256 ay) {
        if (z == 0) return (0, 0);
        uint256 zinv = _primemod(z, pp);
        uint256 zinvsq = mulmod(zinv, zinv, pp);
        uint256 zinvcb = mulmod(zinvsq, zinv, pp);
        ax = mulmod(x, zinvsq, pp);
        ay = mulmod(y, zinvcb, pp);
    }
    /**
     * @dev performs double Jacobian as defined below:
     * https://hyperelliptic.org/EFD/g1p/auto-code/shortw/jacobian-3/doubling/mdbl-2007-bl.op3
     */
    function _jAdd(uint256 p1, uint256 p2, uint256 p3, uint256 q1, uint256 q2, uint256 q3) private pure returns (uint256 r1, uint256 r2, uint256 r3) {
        if (p3 == 0) {
            return (q1, q2, q3);
        }
        if (q3 == 0) {
            return (p1, p2, p3);
        }
        assembly {
            let pd := 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            let z1z1 := mulmod(p3, p3, pd) // Z1Z1 = Z1^2
            let z2z2 := mulmod(q3, q3, pd) // Z2Z2 = Z2^2

            let u1 := mulmod(p1, z2z2, pd) // U1 = X1*Z2Z2
            let u2 := mulmod(q1, z1z1, pd) // U2 = X2*Z1Z1

            let s1 := mulmod(p2, mulmod(z2z2, q3, pd), pd) // S1 = Y1*Z2*Z2Z2
            let s2 := mulmod(q2, mulmod(z1z1, p3, pd), pd) // S2 = Y2*Z1*Z1Z1

            let p3q3 := addmod(p3, q3, pd)

            if lt(u2, u1) { u2 := add(pd, u2) } // u2 = u2+pd

            let h := sub(u2, u1) // H = U2-U1

            let i := mulmod(0x02, h, pd)
            i := mulmod(i, i, pd) // I = (2*H)^2

            let j := mulmod(h, i, pd) // J = H*I
            if lt(s2, s1) { s2 := add(pd, s2) } // u2 = u2+pd

            let rr := mulmod(0x02, sub(s2, s1), pd) // r = 2*(S2-S1)
            r1 := mulmod(rr, rr, pd) // X3 = R^2

            let v := mulmod(u1, i, pd) // V = U1*I
            let j2v := addmod(j, mulmod(0x02, v, pd), pd)
            if lt(r1, j2v) { r1 := add(pd, r1) } // X3 = X3+pd

            r1 := sub(r1, j2v)

            // Y3 = r*(V-X3)-2*S1*J
            let s12j := mulmod(mulmod(0x02, s1, pd), j, pd)

            if lt(v, r1) { v := add(pd, v) }
            r2 := mulmod(rr, sub(v, r1), pd)

            if lt(r2, s12j) { r2 := add(pd, r2) }
            r2 := sub(r2, s12j)

            // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
            z1z1 := addmod(z1z1, z2z2, pd)
            j2v := mulmod(p3q3, p3q3, pd)
            if lt(j2v, z1z1) { j2v := add(pd, j2v) }
            r3 := mulmod(sub(j2v, z1z1), h, pd)
        }
        return (r1, r2, r3);
    }

    // Point doubling on the modified jacobian coordinates
    // http://point-at-infinity.org/ecc/Prime_Curve_Modified_Jacobian_Coordinates.html
    function _jDouble(uint256 x, uint256 y, uint256 z) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        assembly {
            let pd := 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            let z2 := mulmod(z, z, pd)
            let az4 :=
                mulmod(0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC, mulmod(z2, z2, pd), pd)
            let y2 := mulmod(y, y, pd)
            let s := mulmod(0x04, mulmod(x, y2, pd), pd)
            let u := mulmod(0x08, mulmod(y2, y2, pd), pd)
            let m := addmod(mulmod(0x03, mulmod(x, x, pd), pd), az4, pd)
            let twos := mulmod(0x02, s, pd)
            let m2 := mulmod(m, m, pd)
            if lt(m2, twos) { m2 := add(pd, m2) }
            x3 := sub(m2, twos)
            if lt(s, x3) { s := add(pd, s) }
            y3 := mulmod(m, sub(s, x3), pd)
            if lt(y3, u) { y3 := add(pd, y3) }
            y3 := sub(y3, u)
            z3 := mulmod(0x02, mulmod(y, z, pd), pd)
        }
    }

    // From fermats little theorem https://en.wikipedia.org/wiki/Fermat%27s_little_theorem:
    // `a**(p-1) ≡ 1 mod p`. This means that `a**(p-2)` is an inverse of a in Fp.
    function _primemod(uint256 value, uint256 p) private view returns (uint256) {
        return Math.modExp(value, p - 2, p);
    }
}
