package ethash

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"go.uber.org/zap"
	"golang.org/x/crypto/sha3"
)

// copied from https://github.com/ethereum/go-ethereum/blob/7ae6c4a79006ce27b19f144be09af8211c7055e5/consensus/ethash/consensus.go

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header, logger *zap.Logger) (hash common.Hash) {
	sugar := logger.Sugar()
	hasher := sha3.NewLegacyKeccak256()

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
	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	sugar.Debugw("seal hash: ", hash)
	return hash
}
