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

    const proof = {
    a: [
      "0x1650b28d4fa38966a643712524820d514b2f1f257c28fd00a36bac489b59a53c",
      "0x2fc5bcf3a126a4e38482e626d4d42c4b09337470903090ecb5d9dcdecfb1c20c"
    ],
    b: [
      [
        "0x1aa19ef9468f78104426f207f7859670e8fd43d34c102c1b2413024343272675",
        "0x004b42ee247619a1739a7e3926e2eb30abc3d8b9132dc726db697f783a4ec5a0"
      ],
      [
        "0x3040eb92e485f52f9d2daa17997c099c608873e09302f0f76ae7912154472118",
        "0x23bee426e9f13e255fbda633730c861269102ce9adb4cd2f3454d2167d5b81f6"
      ]
    ],
    c: [
      "0x268b06c839b3c549ef6797695aa34f089886726dcf7cc52409f354ab07712535",
      "0x1cce1b2b5efb183879b3b7e0aa2fcb95cd580bf21d47814bb5bb37358acdc200"
    ]
  };

  const inputs = [
    "0x0000000000000000000000000000000000000000000000000000010ed2e36481",
    "0x0000000000000000000000000000000000000000000000000000000055c01236",
    "0x000000000000000000000000000000000000000000000000c7670049269c1046",
    "0x0000000000000000000000000000000000000000000000002d3c5e86f42c6030",
    "0x0000000000000000000000000000000000000000000000009eed72602fc1e618",
    "0x0000000000000000000000000000000000000000000000005efbba44328b9218",
    "0x00000000000000000000000000000000000000000000000081906c2a1206ccb7",
    "0x000000000000000000000000000000000000000000000000b55b1ecb1eb8d1cc",
    "0x0000000000000000000000000000000000000000000000006186d12f9cb1d9a8",
    "0x000000000000000000000000000000000000000000000000cad16f9df8bf7b01",
    "0x0000000000000000000000000000000000000000000000000000010eb1090815",
    "0x0000000000000000000000000000000000000000000000000000000055c0124e",
    "0x000000000000000000000000000000000000000000000000000000001db4b403",
    "0x00000000000000000000000000000000000000000000000000000000f79a2a74",
    "0x000000000000000000000000000000000000000000000000000000009f1706fb",
    "0x0000000000000000000000000000000000000000000000000000000045517e64",
    "0x00000000000000000000000000000000000000000000000000000000974ed7ad",
    "0x0000000000000000000000000000000000000000000000000000000098a565cf",
    "0x00000000000000000000000000000000000000000000000000000000ed047f3f",
    "0x000000000000000000000000000000000000000000000000000000003bbafc00"
  ];

  let check = await relayContract.submitBatch(proof, inputs, { gasLimit: 5000000 });

  const receipt = await check.wait();

  logger.info(receipt);

  const currentBlock = await relayContract.getLastBlock();

  logger.info(currentBlock);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
