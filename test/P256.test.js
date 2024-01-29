const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { prepareSignature } = require('./utils');

describe('P256', function () {
  async function fixture() {
    return { mock: await ethers.deployContract('$P256') };
  }

  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture), prepareSignature());
  });

  it('derivate public from private', async function () {
    expect(await this.mock.$getPublicKey(ethers.toBigInt(this.privateKey))).to.deep.equal(this.publicKey);
  });

  Array(10).fill().forEach((_, i, {length}) => {
    it(`confirm valid signature (run ${i + 1}/${length})`, async function () {
      expect(await this.mock.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.true;
    });

    it(`recover public key (run ${i + 1}/${length})`, async function () {
      expect(await this.mock.$recovery(...this.signature, this.recovery, this.messageHash)).to.deep.equal(this.publicKey);
    });
  });

  it('reject signature with flipped public key coordinates ([x,y] >> [y,x])', async function () {
    this.publicKey.reverse();
    expect(await this.mock.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
  });

  it('reject signature with flipped signature values ([r,s] >> [s,r])', async function () {
    this.signature.reverse();
    expect(await this.mock.$verify(...this.publicKey, ...this.signature, this.messageHash)).to.be.false;
  });

  it('reject signature with invalid message hash', async function () {
    var invalidMessageHash = ethers.hexlify(ethers.randomBytes(32));
    expect(await this.mock.$verify(...this.publicKey, ...this.signature, invalidMessageHash)).to.be.false;
  });
});