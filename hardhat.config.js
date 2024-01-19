require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');

module.exports = {
  solidity: {
    compilers: [
      { version: '0.8.23' },
      { version: '0.7.6' },
      { version: '0.6.12' },
      { version: '0.5.17' },
      { version: '0.4.26' },
    ],
  },
};
