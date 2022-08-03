// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// When running the script with `npx hardhat run <script>` you'll find the Hardhat
// Runtime Environment's members available in the global scope.
import "@nomiclabs/hardhat-ethers";
import { logger } from './utils/logger';
const hre = require('hardhat');

async function main() {
    // Hardhat always runs the compile task when running scripts with its command
    // line interface.
    //
    // If this script is run directly using `node` you may want to call compile
    // manually to make sure everything is compiled
    // await hre.run('compile');
    logger.info(process.pid);

    const weird = await hre.ethers.getContractFactory("BN256G2");
    const weirder = await weird.deploy();

    // We get the contract to deploy
    const RelayContract = await hre.ethers.getContractFactory("RelayContract", {
        libraries: {
            BN256G2: weirder.address
        }
    });
    const relayContract = await RelayContract.deploy();

    logger.info("RelayContract deployed to:", relayContract.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
