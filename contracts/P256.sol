// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import { Math } from "./Math.sol";

/**
 * @dev Implementation of secp256r1 verification and recovery functions.
 *
 * Based on
 * - https://github.com/itsobvioustech/aa-passkeys-wallet/blob/main/src/Secp256r1.sol
 * Which is heavily inspired from
 * - https://github.com/maxrobot/elliptic-solidity/blob/master/contracts/Secp256r1.sol
 * - https://github.com/tdrerup/elliptic-curve-solidity/blob/master/contracts/curves/EllipticCurve.sol
 */
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
    uint256 constant aa = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC;
    uint256 constant bb = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;
    uint256 constant pp2 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFD;
    uint256 constant nn2 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC63254F;
    uint256 constant pp1div4 = 0x3fffffffc0000000400000000000000000000000400000000000000000000000;

    /**
     * @dev signature verification
     * @param Qx - public key coordinate X
     * @param Qy - public key coordinate Y
     * @param r - signature half R
     * @param s - signature half S
     * @param e - hashed message
     */
    function verify(uint256 Qx, uint256 Qy, uint256 r, uint256 s, uint256 e) internal view returns (bool) {
        if (r == 0 || r >= nn || s == 0 || s >= nn || !isOnCurve(Qx, Qy)) return false;

        JPoint[16] memory points = _preComputeJacobianPoints(Qx, Qy);
        uint256 w = _invModN(s);
        uint256 u1 = mulmod(e, w, nn);
        uint256 u2 = mulmod(r, w, nn);
        (uint256 x, ) = _jMultShamir(points, u1, u2);
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
        if (r == 0 || r >= nn || s == 0 || s >= nn || v > 1) return (0, 0);

        uint256 rx = r;
        uint256 ry2 = addmod(mulmod(addmod(mulmod(rx, rx, pp), aa, pp), rx, pp), bb, pp); // weierstrass equation y² = x³ + a.x + b
        uint256 ry = Math.modExp(ry2, pp1div4, pp); // This formula for sqrt work because pp ≡ 3 (mod 4)
        if (mulmod(ry, ry, pp) != ry2) return (0, 0); // Sanity check
        if (ry % 2 != v % 2) ry = pp - ry;

        JPoint[16] memory points = _preComputeJacobianPoints(rx, ry);
        uint256 w = _invModN(r);
        uint256 u1 = mulmod(nn - (e % nn), w, nn);
        uint256 u2 = mulmod(s, w, nn);
        (uint256 x, uint256 y) = _jMultShamir(points, u1, u2);
        return (x, y);
    }

    /**
     * @dev address recovery
     * @param r - signature half R
     * @param s - signature half S
     * @param v - signature recovery param
     * @param e - hashed message
     */
    function recoveryAddress(uint256 r, uint256 s, uint8 v, uint256 e) internal view returns (address) {
        (uint256 Qx, uint256 Qy) = recovery(r, s, v, e);
        return getAddress(Qx, Qy);
    }

    /**
     * @dev derivate public key
     * @param privateKey - private key
     */
    function getPublicKey(uint256 privateKey) internal view returns (uint256, uint256) {
        (uint256 x, uint256 y, uint256 z) = _jMult(gx, gy, 1, privateKey);
        return _affineFromJacobian(x, y, z);
    }

    /**
     * @dev Hash public key into an address
     * @param Qx - public key coordinate X
     * @param Qy - public key coordinate Y
     */
    function getAddress(uint256 Qx, uint256 Qy) internal pure returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, Qx)
            mstore(0x20, Qy)
            result := keccak256(0x00, 0x40)
        }
    }

    /**
     * @dev check if a point is on the curve.
     */
    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            let p := pp
            let lhs := mulmod(y, y, p)
            let rhs := addmod(mulmod(addmod(mulmod(x, x, p), aa, p), x, p), bb, p)
            result := eq(lhs, rhs)
        }
    }

    /**
     * @dev Reduce from jacobian to affine coordinates
     * @param jx - jacobian coordinate x
     * @param jy - jacobian coordinate y
     * @param jz - jacobian coordinate z
     * @return ax - affine coordiante x
     * @return ay - affine coordiante y
     */
    function _affineFromJacobian(uint256 jx, uint256 jy, uint256 jz) private view returns (uint256 ax, uint256 ay) {
        if (jz == 0) return (0, 0);
        uint256 zinv = _invModP(jz);
        uint256 zzinv = mulmod(zinv, zinv, pp);
        uint256 zzzinv = mulmod(zzinv, zinv, pp);
        ax = mulmod(jx, zzinv, pp);
        ay = mulmod(jy, zzzinv, pp);
    }

    /**
     * @dev Point addition on the jacobian coordinates
     * https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
     */
    function _jAdd(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2, uint256 z2) private pure returns (uint256 x3, uint256 y3, uint256 z3) {
        if (z1 == 0) {
            return (x2, y2, z2);
        }
        if (z2 == 0) {
            return (x1, y1, z1);
        }
        /// @solidity memory-safe-assembly
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

            // x' = r²-h³-2*u1*h²
            x3 := addmod(addmod(mulmod(r, r, p), sub(p, hhh), p), sub(p, mulmod(2, mulmod(u1, hh, p), p)), p)
            // y' = r*(u1*h²-x')-s1*h³
            y3 := addmod(mulmod(r,addmod(mulmod(u1, hh, p), sub(p, x3), p), p), sub(p, mulmod(s1, hhh, p)), p)
            // z' = h*z1*z2
            z3 := mulmod(h, mulmod(z1, z2, p), p)
        }
    }

    /**
     * @dev Point doubling on the jacobian coordinates
     * https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates
     */
    function _jDouble(uint256 x, uint256 y, uint256 z) private pure returns (uint256 x2, uint256 y2, uint256 z2) {
        /// @solidity memory-safe-assembly
        assembly {
            let p := pp
            let yy := mulmod(y, y, p)
            let zz := mulmod(z, z, p)
            let s := mulmod(4, mulmod(x, yy, p), p) // s = 4*x*y²
            let m := addmod(mulmod(3, mulmod(x, x, p), p), mulmod(aa, mulmod(zz, zz, p), p), p) // m = 3*x²+a*z⁴

            // x' = m²-2*s
            x2 := addmod(mulmod(m, m, p), sub(p, mulmod(2, s, p)), p)
            // y' = m*(s-x')-8*y⁴
            y2 := addmod(mulmod(m, addmod(s, sub(p, x2), p), p), sub(p, mulmod(8, mulmod(yy, yy, p), p)), p)
            // z' = 2*y*z
            z2 := mulmod(2, mulmod(y, z, p), p)
        }
    }

    /**
     * @dev Point multiplication on the jacobian coordinates
     */
    function _jMult(uint256 x, uint256 y, uint256 z, uint256 k) private pure returns (uint256 x2, uint256 y2, uint256 z2) {
        unchecked {
            for (uint256 i = 0; i < 256; ++i) {
                if (z > 0) {
                    (x2, y2, z2) = _jDouble(x2, y2, z2);
                }
                if (k >> 255 > 0) {
                    (x2, y2, z2) = _jAdd(x2, y2, z2, x, y, z);
                }
                k <<= 1;
            }
        }
    }

    /**
     * @dev Compute P·u1 + Q·u2 using the precomputed points for P and Q (see {_preComputeJacobianPoints}).
     *
     * Uses Strauss Shamir trick for EC multiplication
     * https://stackoverflow.com/questions/50993471/ec-scalar-multiplication-with-strauss-shamir-method
     * we optimise on this a bit to do with 2 bits at a time rather than a single bit
     * the individual points for a single pass are precomputed
     * overall this reduces the number of additions while keeping the same number of doublings
     */
    function _jMultShamir(JPoint[16] memory points, uint256 u1, uint256 u2) private view returns (uint256, uint256) {
        uint256 x = 0;
        uint256 y = 0;
        uint256 z = 0;
        unchecked {
            for (uint256 i = 0; i < 128; ++i) {
                if (z > 0) {
                    (x, y, z) = _jDouble(x, y, z);
                    (x, y, z) = _jDouble(x, y, z);
                }
                // Read 2 bits of u1, and 2 bits of u2. Combining the two give a lookup index in the table.
                uint256 pos = (u1 >> 252 & 0xc) | (u2 >> 254 & 0x3);
                if (pos > 0) {
                    (x, y, z) = _jAdd(x, y, z, points[pos].x, points[pos].y, points[pos].z);
                }
                u1 <<= 2;
                u2 <<= 2;
            }
        }
        return _affineFromJacobian(x, y, z);
    }

    /**
     * @dev Precompute a matrice of usefull jacobian points associated to a given P. This can be seen as a 4x4 matrix
     * that contains combinaison of P and G (generator) up to 3 times each. See table bellow:
     *
     * ┌────┬─────────────────────┐
     * │  i │  0    1     2     3 │
     * ├────┼─────────────────────┤
     * │  0 │  0    p    2p    3p │
     * │  4 │  g  g+p  g+2p  g+3p │
     * │  8 │ 2g 2g+p 2g+2p 2g+3p │
     * │ 12 │ 3g 3g+p 3g+2p 3g+3p │
     * └────┴─────────────────────┘
     */
    function _preComputeJacobianPoints(uint256 px, uint256 py) private pure returns (JPoint[16] memory points) {
        points[0x00] = JPoint(0, 0, 0);
        points[0x01] = JPoint(px, py, 1);
        points[0x04] = JPoint(gx, gy, 1);
        points[0x02] = _jDoublePoint(points[0x01]);
        points[0x08] = _jDoublePoint(points[0x04]);
        points[0x03] = _jAddPoint(points[0x01], points[0x02]);
        points[0x05] = _jAddPoint(points[0x01], points[0x04]);
        points[0x06] = _jAddPoint(points[0x02], points[0x04]);
        points[0x07] = _jAddPoint(points[0x03], points[0x04]);
        points[0x09] = _jAddPoint(points[0x01], points[0x08]);
        points[0x0a] = _jAddPoint(points[0x02], points[0x08]);
        points[0x0b] = _jAddPoint(points[0x03], points[0x08]);
        points[0x0c] = _jAddPoint(points[0x04], points[0x08]);
        points[0x0d] = _jAddPoint(points[0x01], points[0x0c]);
        points[0x0e] = _jAddPoint(points[0x02], points[0x0c]);
        points[0x0f] = _jAddPoint(points[0x03], points[0x0C]);
    }

    function _jAddPoint(JPoint memory p1, JPoint memory p2) private pure returns (JPoint memory) {
        (uint256 x, uint256 y, uint256 z) = _jAdd(p1.x, p1.y, p1.z, p2.x, p2.y, p2.z);
        return JPoint(x, y, z);
    }

    function _jDoublePoint(JPoint memory p) private pure returns (JPoint memory) {
        (uint256 x, uint256 y, uint256 z) = _jDouble(p.x, p.y, p.z);
        return JPoint(x, y, z);
    }

    /**
     *@dev From Fermat's little theorem https://en.wikipedia.org/wiki/Fermat%27s_little_theorem:
     * `a**(p-1) ≡ 1 mod p`. This means that `a**(p-2)` is an inverse of a in Fp.
     */
    function _invModN(uint256 value) private view returns (uint256) {
        return Math.modExp(value, nn2, nn);
    }

    function _invModP(uint256 value) private view returns (uint256) {
        return Math.modExp(value, pp2, pp);
    }
}
