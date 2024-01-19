// require('dotenv').config();

// const { argv } = require('yargs/yargs')(process.argv.slice(2))
//   .env('')
//   .options({
//     // modules
//     coverage:      { type: 'boolean', default: false },
//     report:        { type: 'boolean', default: false },
//     // compilations
//     compiler:      { type: 'string', default: '0.8.21' },
//     evmVersion:    { type: 'string', default: 'shanghai' }, // paris?
//     mode:          { type: 'string', choices: ['production', 'development'], default: 'production' },
//     runs:          { type: 'number', default: 200 },
//     viaIr:         { type: 'boolean', default: false },
//     revertStrings: { type: 'string', choices: ['default', 'strip'], default: 'default' },
//     // chain
//     chainId:       { type: 'number', default: 1337 },
//     hardfork:      { type: 'string', default: 'shanghai' }, // merge?
//     slow:          { type: 'boolean', default: false },
//     // APIs
//     coinmarketcap: { type: 'string' },
//   });

require('@nomicfoundation/hardhat-chai-matchers');
require('@nomicfoundation/hardhat-ethers');
// require('@openzeppelin/hardhat-upgrades');
// require('hardhat-gas-reporter');
// require('solidity-coverage');

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
  // gasReporter: {
  //   currency: 'USD',
  //   coinmarketcap: argv.coinmarketcap,
  // },
};
