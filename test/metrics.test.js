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

  for (const { contract, signature, args, expected, skip } of  [{
    contract: '$Secp256r1_itsobvioustech',
    signature: '$Verify',
    args: ({ publicKey, signature, messageHash }) => [[...publicKey, "placeholder"], ...signature, messageHash],
    expected: () => true,
  },{
    skip: true,
    contract: '$Secp256r1_maxrobot',
    signature: '$Verify',
    args: ({ publicKey, signature, messageHash }) => [...publicKey, signature, messageHash],
    expected: () => true,
  },{
    contract: '$FCL_ecdsa',
    signature: '$ecdsa_verify',
    args: ({ publicKey, signature, messageHash }) => [messageHash, ...signature, ...publicKey],
    expected: () => true,
  },{
    skip: true,
    contract: '$FCL_ecdsa',
    signature: '$ec_recover_r1',
    args: ({ signature, recovery, messageHash }) => [messageHash, recovery + 27, ...signature],
    expected: ({ publicKey }) => '0x' + ethers.keccak256(ethers.concat(publicKey)).slice(-40),
  },{
    contract: '$P256',
    signature: '$verify',
    args: ({ publicKey, signature, messageHash }) => [...publicKey, ...signature, messageHash],
    expected: () => true,
  },{
    skip: true,
    contract: '$P256',
    signature: '$recovery',
    args: ({ signature, recovery, messageHash }) => [...signature, recovery, messageHash],
    expected: ({ publicKey }) => publicKey,
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
          expect(await this.mock.getFunction(signature).staticCall(...args(this))).to.deep.equal(expected(this));
          this.metrics[key].push(await this.mock.getFunction(signature).estimateGas(...args(this)));
        });
      });
    });
  }
});
