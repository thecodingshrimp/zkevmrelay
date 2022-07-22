pragma solidity 0.8.0

import "../zok/output/verifier.sol" as zkVerifier;

contract RelayContract {

    struct Batch {
        uint256 headerHash; // Hash of last block header included in batch
        uint256[5] blockHeader;
        uint256 cumDifficulty;
        uint256 merkleRoot;
        mapping(uint256 => uint256[5]) intermediaryHeader;
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

    constructor() public {
        // add first Ethereum block 
        Branch storage mainChain =  branches[numBranches++];

        // TODO: decide which information should be inside the header on-chain
        Batch storage batch = mainChain.batchChain[mainChain.numBatchChain++];
        batch.headerHash = 0x0

        batch.blockHeader = [
            0,
            0,
            0,
            0,
            0
        ];

        verifier = new zkVerifier.Verifier()
    }

    function submitBatch(uint[12] memory input)
    public
    returns (bool r) {
        require(verifyBatchCorrectnex)
    }

    function verifyBatchCorrectness(
        zkVerifier.Proof proof,
        uint[12] memory input,
        uint branchId,
        uint256 batchHeight,
        uint256 offset
    ) 
    private 
    returns (bool) {
        // Verify the correctness of the zkSNARK computation
        require(verifier.verifyTx(proof, input), 'Could not verify tx');
    }
}