package ethash

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	ethashmerkletree "github.com/thecodingshrimp/ethash-merkle-tree-go"
	"go.uber.org/zap"
)

func GenerateZokratesBatchParameters(firstBlockNumber uint64, batchSize uint64, geth *ethclient.Client, datasetMTPath string, logger *zap.Logger) string {
	// generate cache
	seed := ethash.SeedHash(firstBlockNumber)
	cacheSize := calcCacheSize(int(firstBlockNumber) / epochLength)
	cache := make([]uint32, cacheSize/4)
	generateCache(cache, (firstBlockNumber)/epochLength, seed)

	var (
		rlpHeaders string
		u32Values  string
		u32Indexes string
		u32Proofs  string
		u32MTRoot  string
	)

	// init merkle tree of datasets
	merkleTree := ethashmerkletree.NewMerkleTree(datasetMTPath, int(firstBlockNumber), false, 0, logger)

	// encode mt root in u32
	u32MTRoot = fmt.Sprintf("%d", binary.BigEndian.Uint32(merkleTree.Hashes[0][:4]))
	for j := 4; j < len(merkleTree.Hashes[0]); j += 4 {
		u32MTRoot = fmt.Sprintf("%s %d", u32MTRoot, binary.BigEndian.Uint32(merkleTree.Hashes[0][j:j+4]))
	}
	for i := 0; i < int(batchSize); i++ {
		// getting current block
		head, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(firstBlockNumber+uint64(i))))

		// rlp encode complete header
		header_rlp_64bit_encoded := rlpEncodedHeader(head, logger)

		// add u64 encoded header to headerHashString
		headerHash := SealHash(head, logger)
		rlpHeaders = fmt.Sprintf("%s %s", rlpHeaders, header_rlp_64bit_encoded)

		// getting all required datasetIndexes
		_, _, datasetIndexes := hashimotoLight(calcDatasetSize(int((firstBlockNumber+uint64(i))/epochLength)), cache, headerHash.Bytes(), head.Nonce.Uint64())
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
	head, _ := geth.HeaderByNumber(context.Background(), big.NewInt(int64(firstBlockNumber-1)))

	parentHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		parentHash[i] = head.Hash()[i]
	}
	var parentHashString string
	for i := 0; i < 32; i += 8 {
		parentHashString = fmt.Sprintf("%s %d", parentHashString, binary.BigEndian.Uint64(parentHash[i:i+8]))
	}
	return fmt.Sprintf("%d %d%s%s%s%s%s", head.Difficulty.Uint64(), head.Time, parentHashString, rlpHeaders, u32Values, u32Indexes, u32Proofs)
}

func rlpEncodedHeader(header *types.Header, logger *zap.Logger) string {
	sugar := logger.Sugar()
	enc := []interface{}{
		header.ParentHash,
		header.UncleHash,
		header.Coinbase,
		header.Root,
		header.TxHash,
		header.ReceiptHash,
		header.Bloom,
		header.Difficulty,
		header.Number,
		header.GasLimit,
		header.GasUsed,
		header.Time,
		header.Extra,
	}
	if header.BaseFee != nil {
		enc = append(enc, header.BaseFee)
	}
	enc = append(enc, header.MixDigest)
	enc = append(enc, header.Nonce)

	rlpEncodedHeader, _ := rlp.EncodeToBytes(enc)
	var rlp64bitEncodedHeader string
	for i := 0; i < 71; i++ {
		if i*8 <= len(rlpEncodedHeader)-8 {
			rlp64bitEncodedHeader = fmt.Sprintf("%s %d", rlp64bitEncodedHeader, binary.BigEndian.Uint64(rlpEncodedHeader[i*8:i*8+8]))
		} else if i*8 < len(rlpEncodedHeader) {
			rlp64bitEncodedHeader = fmt.Sprintf("%s %d", rlp64bitEncodedHeader, binary.BigEndian.Uint64(append(rlpEncodedHeader[i*8:], make([]byte, 8-len(rlpEncodedHeader[i*8:]))...)))
		} else {
			rlp64bitEncodedHeader = fmt.Sprintf("%s %d", rlp64bitEncodedHeader, 0)
		}
	}
	sugar.Debugw(rlp64bitEncodedHeader)
	return rlp64bitEncodedHeader
}
