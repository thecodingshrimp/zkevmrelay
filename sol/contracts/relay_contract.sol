// SPDX-License-Identifier: LGPL-3.0-only
// This file is LGPL3 Licensed
pragma solidity 0.8.0;

// todo change import depending on hash function + batch size + other stuff.
import "./verifier_batch_1_poseidon_ark_gm17.sol" as zkVerifier;
import "hardhat/console.sol";

contract RelayContract {
    uint256 constant BATCH_SIZE = 1;

    struct BlockHeader {
        uint256 headerHash;
        uint64 diff;
        uint64 time;
        uint256 txRoot;
    }

    struct Batch {
        BlockHeader lastBlockHeader; // last block header in batch
        uint256 cumDifficulty; // todo do i need that
        uint256 merkleRoot;
        mapping(uint256 => uint256) intermediaryHeaderTxRoots;
    }

     struct Branch {
        uint256 startingAtBatchHeight;
        //Batch[] batchChain;
        uint numBatchChain;
        mapping (uint => Batch) batchChain;
    }

    uint numBranches;
    mapping (uint => Branch) branches;

    zkVerifier.Verifier private verifier;

    constructor() {
        // add first Ethereum block 
        Branch storage mainChain = branches[numBranches++];

        // todo search for a block number to start from where it has transactions.
        Batch storage batch = mainChain.batchChain[mainChain.numBatchChain++];
        batch.lastBlockHeader.headerHash = 0xc7670049269c10462d3c5e86f42c60309eed72602fc1e6185efbba44328b9218;
        batch.lastBlockHeader.diff = 1163179287681;
        batch.lastBlockHeader.time = 1438650934;
        batch.lastBlockHeader.txRoot = 0x0;

        verifier = new zkVerifier.Verifier();
    }

    function getLastBlock()
    view
    public
    returns (uint) {
        return branches[0].batchChain[branches[0].numBatchChain/BATCH_SIZE - 1].lastBlockHeader.headerHash;
    }

    // proof contains parameters a, b, c
    // input contains public inputs and outputs from program
    /**
     Input array:
     0: parent_diff
     1: parent_time
     2-5: parent_hash (u64 array)
     6-9: last_block_header_hash (u64 array)
     10: last_block_diff
     11: last_block_time
     12-19: merkle_root (u32 array)
     */
    function submitBatch(
        zkVerifier.Verifier.Proof memory proof,
        uint[20] memory input
    )
    public
    returns (bool r) {
        require(verifyBatchCorrectness(proof, input, 0, branches[0].numBatchChain, 0), "Could not verify batch correctness");

        Branch storage mainChain = branches[0];
        Batch storage batch = mainChain.batchChain[mainChain.numBatchChain];
        
        createBatch(input, mainChain, batch);

        emit AddedNewBatch((branches[0].numBatchChain - 1));

        return true;
    }

    function verifyBatchCorrectness(
        zkVerifier.Verifier.Proof memory proof,
        uint[20] memory input,
        uint branchId,
        uint256 batchHeight,
        uint256 offset
    ) 
    view
    private 
    returns (bool) {
        // Verify the correctness of the zkSNARK computation
        require(verifier.verifyTx(proof, input), "Could not verify tx");

        // Verify that this batch is the successor of last batch.
        uint256 parent_hash = u64_array_to_u256([uint64(input[2]), uint64(input[3]), uint64(input[4]), uint64(input[5])]);
        // console.log(parent_hash);
        require(parent_hash == branches[branchId].batchChain[batchHeight - offset - 1].lastBlockHeader.headerHash, "Parent hash from validated batch is not the last saved block.");
        // Verify time and difficulty from last block
        require(input[0] == branches[branchId].batchChain[batchHeight - offset - 1].lastBlockHeader.diff, "Parent diff from validated batch is not the same as last saved block.");
        require(input[1] == branches[branchId].batchChain[batchHeight - offset - 1].lastBlockHeader.time, "Parent time from validated batch is not the same as last saved block.");

        return true;
    }

    function createBatch(
        uint[20] memory input, 
        Branch storage chain, 
        Batch storage batch
    ) 
    internal 
    {
        uint256 lastBlockHash = u64_array_to_u256([uint64(input[6]), uint64(input[7]), uint64(input[8]), uint64(input[9])]);
        uint256 merkleRoot = u32_array_to_u256([uint32(input[12]), uint32(input[13]), uint32(input[14]), uint32(input[15]), uint32(input[16]), uint32(input[17]), uint32(input[18]), uint32(input[19])]);
        
        batch.lastBlockHeader.headerHash = lastBlockHash;
        batch.lastBlockHeader.diff = uint64(input[10]);
        batch.lastBlockHeader.time = uint64(input[11]);
        batch.cumDifficulty = chain.batchChain[chain.numBatchChain - 1].cumDifficulty + input[10];
        batch.merkleRoot = merkleRoot;
        chain.numBatchChain++;
    }

    function u32_array_to_u256(
        uint32[8] memory array
    )
    private
    pure
    returns(uint256 value) {
        for (uint i = 0; i < 8; i++) {
            value = value + (uint(array[7-i]) << (i * 32));
        }
    }

    function u64_array_to_u256(
        uint64[4] memory array
    )
    private
    pure
    returns(uint256 value) {
        for (uint i = 0; i < 4; i++) {
            value = value + (uint(array[3-i]) << (i * 64));
        }
    }

    event AddedNewBatch(uint256 batchHeight);
}