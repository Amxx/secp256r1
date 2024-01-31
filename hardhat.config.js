const { argv } = require('yargs/yargs')()
  .env('')
  .options({ runs: { type: 'number', default: 200 }});

require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
require('hardhat-exposed');

module.exports = {
  solidity: {
    compilers: [
      { version: '0.8.23', settings: { optimizer: { enabled: true, runs: argv.runs }} },
      { version: '0.7.6',  settings: { optimizer: { enabled: true, runs: argv.runs }} },
      { version: '0.6.12', settings: { optimizer: { enabled: true, runs: argv.runs }} },
      { version: '0.5.17', settings: { optimizer: { enabled: true, runs: argv.runs }} },
      { version: '0.4.26', settings: { optimizer: { enabled: true, runs: argv.runs }} },
    ],
  },
  exposed: {
    exclude: [],
  },
};
