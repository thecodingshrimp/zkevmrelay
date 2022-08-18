const { expect } = require("chai");
const { ethers } = require("hardhat");
const hre = require('hardhat');
import { BN256G2, RelayContract, Verifier } from '../src-gen/types';
import * as fs from 'fs';
import { logger } from '../scripts/utils/logger';

type Proof = {
    proof: Verifier.ProofStruct,
    inputs: []
};

// todo fix repetitive code
describe('RelayContract', async () => {
    let bn256g2: BN256G2;
    const MAX_BATCH_SIZE = 5;
    const hash_functions = ['poseidon', 'pedersen'];

    before(async () => {
        // todo deploy weird contract from ark backend. (BN256G2)
        const BN256G2 = await hre.ethers.getContractFactory('BN256G2');
        bn256g2 = await BN256G2.deploy();
    });
    
    it("Should test all batch submissions to an ark based proof", async () => {
        // const provingSchemes = ['G16', 'MARLIN'];
        const provingSchemes = ['G16'];
        const backend = 'ARK';

        // GM17 needs extra care since it requires the inclusion of an additional library (BN256G2)
        await exec_eval(backend, ['GM17'], 'poseidon', MAX_BATCH_SIZE-1, true);
        await exec_eval(backend, ['GM17'], 'pedersen', MAX_BATCH_SIZE, true);

        await exec_eval(backend, provingSchemes, 'pedersen', MAX_BATCH_SIZE, false);
        await exec_eval(backend, provingSchemes, 'poseidon', MAX_BATCH_SIZE-1, false);
    });

    it("Should test all batch submissions from a bellman based proof", async () => {
        const provingSchemes = ['G16'];
        const backend = 'BELLMAN';
        await exec_eval(backend, provingSchemes, 'poseidon', MAX_BATCH_SIZE-1, false);
        await exec_eval(backend, provingSchemes, 'pedersen', MAX_BATCH_SIZE, false);
    });

    const exec_eval = async (backend: string, provingSchemes: string[], hash_function: string, MAX_BATCH_SIZE: number, enable_bn256g2: boolean) => {
        for (let provingScheme of provingSchemes) {
            for (let i = 0; i < MAX_BATCH_SIZE; i++) {
                const currBatchSize = i+1;
                // deploy relay contract
                const currRelayContractName = `RelayContract${currBatchSize}${hash_function.toUpperCase()}${backend.toUpperCase()}${provingScheme.toUpperCase()}`;
                const CurrRelayContractFactory = await hre.ethers.getContractFactory(currRelayContractName, {
                    libraries: enable_bn256g2 ? { BN256G2: bn256g2.address } : {}
                });
                const currRelayContract: RelayContract = await CurrRelayContractFactory.deploy({ gasLimit: 30000000 });

                // submit proof
                const proofFile: string = fs.readFileSync(`../zok/output/proofs/proof_batch_verifier_${currBatchSize}_${hash_function.toLowerCase()}_${backend.toLowerCase()}_${provingScheme.toLowerCase()}.json`).toString();
                const proof: Proof = JSON.parse(proofFile)
                const check = await currRelayContract.submitBatch(proof.proof, proof.inputs);
                const receipt = await check.wait();
                // logger.info(receipt.gasUsed.toNumber());
                // todo record gas
            }
        }
    }
});
