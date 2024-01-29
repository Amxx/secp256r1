const { ethers } = require('hardhat');
const { expect } = require('chai');
const { secp256r1 } = require('@noble/curves/p256');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { prepareSignature } = require('./utils');

const RUN_COUNT = 10;

describe('gas metrics', function () {
  before(async function () {
    this.metrics = {};
  });

  after(async function () {
    Object.entries(this.metrics)
      .filter(([ _, estimates]) => estimates.length > 0)
      .map(([ key, estimates]) => [key, estimates.map(Number).reduce((a, b) => a + b, 0) / estimates.length])
      .sort(([, a], [, b]) => a - b)
      .forEach(([ key, average], i) => console.log(`[${i}] ${~~average} --- ${key}`));
  });

  for (const { contract, signature, args, skip } of  [{
    contract: '$Secp256r1_reference',
    signature: '$Verify',
    args: (publicKey, signature, digest) => [[...publicKey, "placeholder"], ...signature, digest],
  },{
    contract: '$Secp256r1_maxrobot',
    signature: '$Verify',
    args: (publicKey, signature, digest) => [...publicKey, signature, digest],
  },{
    contract: '$FCL_ecdsa',
    signature: '$ecdsa_verify',
    args: (publicKey, signature, digest) => [digest, ...signature, ...publicKey],
  },{
    contract: '$FCL_ecdsa_utils',
    signature: '$ecdsa_verify',
    args: (publicKey, signature, digest) => [digest, signature, ...publicKey],
  },{
    contract: '$P256',
    signature: '$verify',
    args: (publicKey, signature, digest) => [...publicKey, ...signature, digest],
  }]) {
    if (skip) continue;

    const key = `${contract}.${signature}`;
    describe(`${contract}.${signature}`, function () {
      async function fixture() {
        return { mock: await ethers.deployContract(contract) };
      }

      before(function () {
        this.metrics[key] = [];
      });

      beforeEach(async function () {
        Object.assign(this, await loadFixture(fixture), prepareSignature());
      });

      Array(RUN_COUNT).fill().forEach((_, i, {length}) => {
        it(`run ${i + 1}/${length}`, async function () {
          expect(await this.mock.getFunction(signature).staticCall(...args(this.publicKey, this.signature, this.messageHash))).to.be.true;
          this.metrics[key].push(await this.mock.getFunction(signature).estimateGas(...args(this.publicKey, this.signature, this.messageHash)));
        });
      });
    });
  }
});
