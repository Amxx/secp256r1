require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');

module.exports = {
  solidity: {
    compilers: [
      { version: '0.8.23', settings: { optimizer: { enabled: true, runs: 200 }} },
      { version: '0.7.6',  settings: { optimizer: { enabled: true, runs: 200 }} },
      { version: '0.6.12', settings: { optimizer: { enabled: true, runs: 200 }} },
      { version: '0.5.17', settings: { optimizer: { enabled: true, runs: 200 }} },
      { version: '0.4.26', settings: { optimizer: { enabled: true, runs: 200 }} },
    ],
  },
};
