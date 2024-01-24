const { ethers } = require('hardhat');
const { expect } = require('chai');
const { secp256r1 } = require('@noble/curves/p256');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

const names = [
  '$P256',
  'Secp256r1',
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
    before(function () {
      this.estimations = {
        'EllipticCurve.validateSignature': [],
        'Secp256r1.Verify': [],
        'P256.verify': [],
      };
    });

    after(function () {
      Object.entries(this.estimations).filter(([ name, estimates ]) => estimates.length).forEach(([ name, estimates ]) => {
        const average = estimates.reduce((a, b) => a + b, 0n) / ethers.toBigInt(estimates.length);
        console.log(`[average gas cost] ${name}: ${average}`);
      });
    })

    beforeEach(async function () {
      const messageHash = ethers.hexlify(ethers.randomBytes(32));
      const privateKey = secp256r1.utils.randomPrivateKey();
      const publicKey = [
          secp256r1.getPublicKey(privateKey, false).slice(0x01, 0x21),
          secp256r1.getPublicKey(privateKey, false).slice(0x21, 0x41),
      ].map(ethers.hexlify)

      const { r, s } = secp256r1.sign(messageHash.replace(/0x/, ''), privateKey);
      const signature = [ r, s ].map(v => ethers.toBeHex(v, 32));

      Object.assign(this, { messageHash, privateKey, publicKey, signature });
    });

    it.skip('confirm that a valid point is on the curve', async function () {
      let x = '0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      let y = '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      expect(await this.EllipticCurve.isOnCurve(x, y)).to.be.true;
    });

    it.skip('reject that an invalid point is on the curve', async function () {
      let x = '0x3B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296';
      let y = '0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5';
      expect(await this.EllipticCurve.isOnCurve(x, y)).to.be.false;
    });

    it('derivate public from private', async function () {
      expect(await this.$P256.$getPublicKey(ethers.toBigInt(this.privateKey))).to.deep.equal(this.publicKey);
    });

    Array(10).fill().forEach((_, i, {length}) => {
      it(`confirm valid signature (run ${i + 1}/${length})`, async function () {
        expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.true;
        expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.true;
        expect(await this.$P256.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.true;

        this.estimations['EllipticCurve.validateSignature'].push(await this.EllipticCurve.validateSignature.estimateGas(this.messageHash, this.signature, this.publicKey));
        this.estimations['Secp256r1.Verify'               ].push(await this.Secp256r1.Verify.estimateGas(...this.publicKey, ...this.signature, this.messageHash));
        this.estimations['P256.verify'                    ].push(await this.$P256.$verify.estimateGas(...this.publicKey, ...this.signature, this.messageHash));
      });
    });

    it('reject signature with flipped public key coordinates ([x,y] >> [y,x])', async function () {
      this.publicKey.reverse();
      expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.false;
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.$P256.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
    });

    it('reject signature with flipped signature values ([r,s] >> [s,r])', async function () {
      this.signature.reverse();
      expect(await this.EllipticCurve.validateSignature(this.messageHash, this.signature, this.publicKey)).to.be.false;
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
      expect(await this.$P256.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
    });

    it('reject signature with invalid message hash', async function () {
      var invalidMessageHash = ethers.hexlify(ethers.randomBytes(32));
      expect(await this.EllipticCurve.validateSignature(invalidMessageHash, this.signature, this.publicKey)).to.be.false;
      expect(await this.Secp256r1.Verify(...this.publicKey, ...this.signature, invalidMessageHash)).to.be.false;
      expect(await this.$P256.$verify(...this.publicKey, ...this.signature, invalidMessageHash)).to.be.false;
    });
  });
});
