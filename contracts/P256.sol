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
    function _affineFromJacobian(uint256 jx, uint256 jy, uint256 jz) private view returns (uint256 ax, uint256 ay) {
        if (jz == 0) return (0, 0);
        uint256 zinv = _primemod(jz, pp);
        uint256 zzinv = mulmod(zinv, zinv, pp);
        uint256 zzzinv = mulmod(zzinv, zinv, pp);
        ax = mulmod(jx, zzinv, pp);
        ay = mulmod(jy, zzzinv, pp);
    }

    /**
     * Point addition on the jacobian coordinates
     * https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
     */
    function _jAdd(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2, uint256 z2) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        if (z1 == 0) {
            return (x2, y2, z2);
        }
        if (z2 == 0) {
            return (x1, y1, z1);
        }
        assembly {
            let p := pp
            let zz1 := mulmod(z1, z1, p) // zz1 = z1²
            let zz2 := mulmod(z2, z2, p) // zz2 = z2²
            let u1 := mulmod(x1, zz2, p) // u1 = x1*z2²
            let u2 := mulmod(x2, zz1, p) // u2 = x2*z1²
            let s1 := mulmod(y1, mulmod(zz2, z2, p), p) // s1 = y1*z2³
            let s2 := mulmod(y2, mulmod(zz1, z1, p), p) // s2 = y2*z1³
            let h := addmod(u2, sub(p, u1), p) // h = u2-u1
            let hh := mulmod(h, h, p) // h²
            let hhh := mulmod(h, hh, p) // h³
            let r := addmod(s2, sub(p, s1), p) // r = s2-s1
            let rr := mulmod(r, r, p) // r²

            // x' = r²-H³-2*u1*h²
            x3 := addmod(addmod(rr, sub(p, hhh), p), sub(p, mulmod(2, mulmod(u1, hh, p), p)), p)
            // y' = r*(u1*H²-x')-s1*h³
            y3 := addmod(mulmod(r,addmod(mulmod(u1, hh, p), sub(p, x3), p), p), sub(p, mulmod(s1, hhh, p)), p)
            // z' = h*z1*z2
            z3 := mulmod(h, mulmod(z1, z2, p), p)
        }
    }

    /**
     * Point doubling on the jacobian coordinates
     * https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
     */
    function _jDouble(uint256 x, uint256 y, uint256 z) private pure returns (uint256 x2, uint256 y2, uint256 z2) {
        assembly {
            let p := pp
            let yy := mulmod(y, y, p)
            let zz := mulmod(z, z, p)
            let s := mulmod(4, mulmod(x, yy, p), p) // s = 4*x*y²
            let m := addmod(mulmod(3, mulmod(x, x, p), p), mulmod(a, mulmod(zz, zz, p), p), p) // m = 3*x²+a*z⁴

            // x' = m²-2*s
            x2 := addmod(mulmod(m, m, p), sub(p, mulmod(2, s, p)), p)
            // y' = m*(s-x')-8*y⁴
            y2 := addmod(mulmod(m, addmod(s, sub(p, x2), p), p), sub(p, mulmod(8, mulmod(yy, yy, p), p)), p)
            // z2 = 2*y*z
            z2 := mulmod(2, mulmod(y, z, p), p)
        }
    }

    // From fermats little theorem https://en.wikipedia.org/wiki/Fermat%27s_little_theorem:
    // `a**(p-1) ≡ 1 mod p`. This means that `a**(p-2)` is an inverse of a in Fp.
    function _primemod(uint256 value, uint256 p) private view returns (uint256) {
        return Math.modExp(value, p - 2, p);
    }
}
