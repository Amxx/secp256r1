const { argv } = require('yargs/yargs')()
  .env('')
  .options({
    runs: { type: 'number', default: 200 },
    ir: { type: 'boolean', default: false },
  });

require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
require('hardhat-exposed');

module.exports = {
  solidity: {
    compilers: [
      {
        version: '0.8.23',
        settings: {
          optimizer: {
            enabled: true,
            runs: argv.runs,
          },
          viaIR: argv.ir
        },
      },
    ],
  },
  exposed: {
    exclude: [],
  },
};
