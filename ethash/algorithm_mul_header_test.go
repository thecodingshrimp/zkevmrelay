package ethash

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/assert"
	ethashmerkletree "github.com/thecodingshrimp/ethash-merkle-tree-go"
	"go.uber.org/zap"
)

func TestMultipleHeadersWitnessHashimoto(t *testing.T) {
	// connect to client
	geth, err := ethclient.Dial("https://mainnet.infura.io/v3/6884b6e0a90d42d291b8d3faca1a9ad6")
	assert.Nil(t, err)
	BLOCK_NR := uint64(30001)
	BATCH_SIZE := 1

	// generate cache
	seed := ethash.SeedHash(BLOCK_NR)
	cacheSize := calcCacheSize(int(BLOCK_NR) / epochLength)
	cache := make([]uint32, cacheSize/4)
	generateCache(cache, (BLOCK_NR)/epochLength, seed)

	var (
		rlpHeaders string
		u32Values  string
		u32Indexes string
		u32Proofs  string
		u32MTRoot  string
	)

	// init merkle tree of dataset
	logger, _ := zap.NewDevelopment()
	merkleTree := ethashmerkletree.NewMerkleTree("./", int(BLOCK_NR), false, 0, logger)
	// encode mt root in u32
	u32MTRoot = fmt.Sprintf("%d", binary.BigEndian.Uint32(merkleTree.Hashes[0][:4]))
	for j := 4; j < len(merkleTree.Hashes[0]); j += 4 {
		u32MTRoot = fmt.Sprintf("%s %d", u32MTRoot, binary.BigEndian.Uint32(merkleTree.Hashes[0][j:j+4]))
	}
	for i := 0; i < BATCH_SIZE; i++ {
		// getting current block
		head, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(BLOCK_NR+uint64(i))))
		log.Println("HERE IT IS", head.ParentHash)
		log.Println("HERE IS ALSO THE HASH ITSELF", head.Hash())

		// add u64 encoded header to headerHashString
		headerHash, header_rlp_64bit_encoded := SealHash(head)
		rlpHeaders = fmt.Sprintf("%s %s", rlpHeaders, header_rlp_64bit_encoded)

		// getting all required datasetIndexes
		_, _, datasetIndexes := hashimotoLight(calcDatasetSize(int((BLOCK_NR+uint64(i))/epochLength)), cache, headerHash.Bytes(), head.Nonce.Uint64())
		for _, idx := range datasetIndexes {
			// insert values from dataset item
			values := [2][]byte{merkleTree.Raw64BytesDataElements[idx], merkleTree.Raw64BytesDataElements[idx+1]}
			for _, value := range values {
				for j := 0; j < len(value); j += 4 {
					u32Values = fmt.Sprintf("%s %d", u32Values, binary.BigEndian.Uint32(value[j:j+4]))
				}
			}
			// proof from dataset item
			proof, _ := merkleTree.GetProofByRaw64ByteElementIndex(int(idx))
			for _, element := range proof {
				for j := 0; j < len(element); j += 4 {
					u32Proofs = fmt.Sprintf("%s %d", u32Proofs, binary.BigEndian.Uint32(element[j:j+4]))
				}
			}
			// add index to string
			u32Indexes = fmt.Sprintf("%s %d", u32Indexes, idx)
		}
	}
	// getting parent header
	head, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(BLOCK_NR-1)))
	log.Println("HERE IS THE PARENT", head.Hash())
	parentHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		parentHash[i] = head.Hash()[i]
	}
	var parentHashString string
	for i := 0; i < 32; i += 8 {
		parentHashString = fmt.Sprintf("%s %d", parentHashString, binary.BigEndian.Uint64(parentHash[i:i+8]))
	}
	holyStringer := fmt.Sprintf("%d %d%s%s%s%s%s", head.Difficulty.Uint64(), head.Time, parentHashString, rlpHeaders, u32Values, u32Indexes, u32Proofs)
	log.Println(holyStringer)
}

func TestWitnessHashimotoMultipleHeaders(t *testing.T) {
	geth, err := ethclient.Dial("https://mainnet.infura.io/v3/6884b6e0a90d42d291b8d3faca1a9ad6")
	assert.Nil(t, err)
	BLOCK_NR := uint64(30000)
	for i := 0; i < 2; i++ {
		head, err := geth.HeaderByNumber(context.Background(), big.NewInt(int64(BLOCK_NR+uint64(i))))
		hehe, _ := geth.BlockNumber(context.Background())
		haha, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(hehe)))
		log.Println("Latest block number", haha.Number.Uint64())
		assert.Nil(t, err)
		headerHash, _ := SealHash(head)
		// generate cache
		seed := ethash.SeedHash(BLOCK_NR + uint64(i))
		cacheSize := calcCacheSize(int(BLOCK_NR+uint64(i)) / epochLength)
		cache := make([]uint32, cacheSize/4)
		generateCache(cache, (BLOCK_NR+uint64(i))/epochLength, seed)
		var headerHashString string
		for i := 0; i < len(headerHash.Bytes()); i += 8 {
			headerHashString = fmt.Sprintf("%s %d", headerHashString, binary.BigEndian.Uint64(headerHash.Bytes()[i:i+8]))
		}
		log.Println(headerHashString)
		log.Println(binary.LittleEndian.Uint64(head.Nonce[:]))
		logger, _ := zap.NewDevelopment()
		digest, work, datasetIndexes := hashimotoLight(calcDatasetSize(int((BLOCK_NR+uint64(i))/epochLength)), cache, headerHash.Bytes(), head.Nonce.Uint64())
		merkleTree := ethashmerkletree.NewMerkleTree("./", int(BLOCK_NR+uint64(i)), false, 0, logger)
		merkleProofs := make([]ethashmerkletree.MerkleProof, len(datasetIndexes))
		var (
			u32Values  string
			u32MTRoot  string
			u32Proof   string
			u32Indexes string
		)
		for i, idx := range datasetIndexes {
			proof, err := merkleTree.GetProofByRaw64ByteElementIndex(int(idx))
			assert.Nil(t, err)
			indexes := [2]int{int(idx), int(idx + 1)}
			u32Indexes = fmt.Sprintf("%s %d", u32Indexes, idx)
			values := [2][]byte{merkleTree.Raw64BytesDataElements[idx], merkleTree.Raw64BytesDataElements[idx+1]}
			merkleProofs[i] = *ethashmerkletree.NewMerkleProof(values, indexes, proof, logger)

			for _, value := range values {
				for j := 0; j < len(value); j += 4 {
					u32Values = fmt.Sprintf("%s %d", u32Values, binary.BigEndian.Uint32(value[j:j+4]))
				}
			}
			for _, element := range proof {
				for j := 0; j < len(element); j += 4 {
					u32Proof = fmt.Sprintf("%s %d", u32Proof, binary.BigEndian.Uint32(element[j:j+4]))
				}
			}
		}
		for j := 0; j < len(merkleTree.Hashes[0]); j += 4 {
			u32MTRoot = fmt.Sprintf("%s %d", u32MTRoot, binary.BigEndian.Uint32(merkleTree.Hashes[0][j:j+4]))
		}
		holyStringer := fmt.Sprintf("%s %d %d %s %s %s %s", headerHashString, binary.LittleEndian.Uint64(head.Nonce[:]), BLOCK_NR+uint64(i), u32MTRoot, u32Values, u32Indexes, u32Proof)
		log.Println(holyStringer)
		start := time.Now()
		digestThroughWitness, workThroughWitness := witnessHashimoto(headerHash.Bytes(), head.Nonce.Uint64(), calcDatasetSize(int((BLOCK_NR+uint64(i))/epochLength)), merkleTree.Hashes[0], merkleProofs)
		log.Println("Hashing with witness took", time.Since(start))
		assert.Equal(t, digest, digestThroughWitness)
		assert.Equal(t, work, workThroughWitness)
	}
}
