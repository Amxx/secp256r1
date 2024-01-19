const { ethers } = require('hardhat');
const { expect } = require('chai');
const { secp256r1 } = require('@noble/curves/p256');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const names = [
  'Secp256r1',
  'Secp256r1_v8',
  'EllipticCurve',
];

async function fixture() {
  return Promise.all(
    names.map(name => ethers.deployContract(name).then(instance => [ name, instance ]))
  ).then(Object.fromEntries);
}

describe('secp256r1', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  describe.skip('interfaces', function () {
    for (const name of names) {
      it(name, async function () {
        console.log(this[name].interface.format())
      });
    }
  });

  describe('verify', function () {
    beforeEach(async function () {
      const messageHash = ethers.hexlify(ethers.randomBytes(32));
      const privateKey = secp256r1.utils.randomPrivateKey();
      const publicKey = [
          secp256r1.getPublicKey(privateKey, false).slice(0x01, 0x21),
          secp256r1.getPublicKey(privateKey, false).slice(0x21, 0x41),
      ].map(ethers.hexlify)

      const { r, s } = secp256r1.sign(messageHash.replace(/0x/, ''), privateKey);
      const signature = [ r, s ].map(v => ethers.toBeHex(v, 32));

      Object.assign(this, { messageHash, publicKey, signature });
    });

    it('confirm that a valid point is on the curve', async function () {
      let x = '0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      let y = '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      expect(await this.EllipticCurve.isOnCurve(x, y)).to.be.true;
    });

    it('reject that an invalid point is on the curve', async function () {
      let x = '0x3B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      let y = '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      expect(await this.EllipticCurve.isOnCurve(x, y)).to.be.false;
    });

    it('confirm valid signature', async function () {
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.true;
      expect(await this.Secp256r1_v8.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.true;
      expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.true;

      console.log('Secp256r1.Verify.estimateGas', await this.Secp256r1.Verify.estimateGas(...this.publicKey, ...this.signature, this.messageHash));
      console.log('Secp256r1_v8.Verify.estimateGas', await this.Secp256r1_v8.Verify.estimateGas(...this.publicKey, ...this.signature, this.messageHash));
      console.log('EllipticCurve.validateSignature.estimateGas', await this.EllipticCurve.validateSignature.estimateGas(this.messageHash, this.signature, this.publicKey));
    });

    it('reject signature with flipped public key coordinates ([x,y] >> [y,x])', async function () {
      this.publicKey.reverse();
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.Secp256r1_v8.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.false;
    });

    it('reject signature with flipped signature values ([r,s] >> [s,r])', async function () {
      this.signature.reverse();
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.Secp256r1_v8.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.false;
    });

    it('reject signature with invalid message hash', async function () {
      var invalidMessageHash = ethers.hexlify(ethers.randomBytes(32));
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, invalidMessageHash)).to.be.false;
      expect(await this.Secp256r1_v8.Verify(...this.publicKey, ...this.signature, invalidMessageHash)).to.be.false;
      expect(await this.EllipticCurve.validateSignature(invalidMessageHash, this.signature, this.publicKey)).to.be.false;
    });
  });
});
