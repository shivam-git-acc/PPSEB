require('@nomicfoundation/hardhat-ethers');
const { subtask } = require('hardhat/config');
const { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } = require('hardhat/builtin-tasks/task-names');
// Use the pinned local solc-js; no compiler download during offline startup.
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD).setAction(async ({ solcVersion }) => ({
  compilerPath: require.resolve('solc/soljson.js'), isSolcJs: true,
  version: solcVersion, longVersion: require('solc').version(),
}));
module.exports = {
  solidity: { version: '0.8.28', settings: { viaIR: true, optimizer: { enabled: true, runs: 200 } } },
  paths: { sources: './src', tests: './test', cache: './cache', artifacts: './artifacts' },
  networks: { localhost: { url: 'http://127.0.0.1:8545' } },
};
