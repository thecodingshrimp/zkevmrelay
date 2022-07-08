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

func TestWitnessHashimoto(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	test := isLittleEndian()
	log.Println(test)
	BLOCK_NR := uint64(30000)
	geth, err := ethclient.Dial("http://localhost:8545")
	assert.Nil(t, err)
	head, err := geth.HeaderByNumber(context.Background(), big.NewInt(int64(BLOCK_NR)))
	hehe, _ := geth.BlockNumber(context.Background())
	haha, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(hehe)))
	log.Println(haha.Number.Uint64())
	assert.Nil(t, err)
	headerHash := SealHash(head, logger)
	// generate cache
	seed := ethash.SeedHash(BLOCK_NR)
	cacheSize := calcCacheSize(int(BLOCK_NR) / epochLength)
	cache := make([]uint32, cacheSize/4)
	generateCache(cache, BLOCK_NR/epochLength, seed)
	start := time.Now()
	log.Println("Normal hashing took", time.Since(start))
	var headerHashString string
	for i := 0; i < len(headerHash.Bytes()); i += 8 {
		headerHashString = fmt.Sprintf("%s %d", headerHashString, binary.BigEndian.Uint64(headerHash.Bytes()[i:i+8]))
	}
	log.Println(headerHashString)
	log.Println(binary.LittleEndian.Uint64(head.Nonce[:]))
	digest, work, datasetIndexes := hashimotoLight(calcDatasetSize(int(BLOCK_NR/epochLength)), cache, headerHash.Bytes(), head.Nonce.Uint64())
	merkleTree := ethashmerkletree.NewMerkleTree("./", int(BLOCK_NR), false, 0, logger)
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
	holyStringer := fmt.Sprintf("%s %d %d %s %s %s %s", headerHashString, binary.LittleEndian.Uint64(head.Nonce[:]), BLOCK_NR, u32MTRoot, u32Values, u32Indexes, u32Proof)
	log.Println(holyStringer)
	start = time.Now()
	digestThroughWitness, workThroughWitness := witnessHashimoto(headerHash.Bytes(), head.Nonce.Uint64(), calcDatasetSize(int(BLOCK_NR/epochLength)), merkleTree.Hashes[0], merkleProofs)
	log.Println("Hashing with witness took", time.Since(start))
	assert.Equal(t, digest, digestThroughWitness)
	assert.Equal(t, work, workThroughWitness)
}
