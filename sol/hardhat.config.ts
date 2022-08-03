// require("dotenv").config();
import '@typechain/hardhat';
import '@nomiclabs/hardhat-ethers';
import "@nomicfoundation/hardhat-chai-matchers";
import "@nomiclabs/hardhat-ethers";
import "hardhat-gas-reporter"

// require("solidity-coverage");

import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.0",
  gasReporter: {
    enabled: true
  },
  networks: {
    hardhat: {
      initialBaseFeePerGas: 0, // workaround from https://github.com/sc-forks/solidity-coverage/issues/652#issuecomment-896330136 . Remove when that issue is closed.
    },
    testnet: {
      url: "http://127.0.0.1:9545",
      accounts: [
        '0xdda499efca23a28053aeb3adc77d8fc80fef20bdf357cf3cff1a0d9834986734',
        '0x3eb08228b460a66335dfe37cb3d5466cc330552b605aa61660e04c5032bf1878',
        '0xec3f5214dd1eddcb37a25c11eff5bdbc18367aa76d383d6ede922f5002494256'
    ],
    },
  },
  typechain: {
    outDir: "src-gen/types",
    target: "ethers-v5",
  },
};


// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
// task("accounts", "Prints the list of accounts", async (hre) => {
//   const accounts = await hre.ethers.getSigners();

//   for (const account of accounts) {
//     console.log(account.address);
//   }
// });

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */

export default config;