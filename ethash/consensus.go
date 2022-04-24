package ethash

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"golang.org/x/crypto/sha3"
)

// copied from https://github.com/ethereum/go-ethereum/blob/7ae6c4a79006ce27b19f144be09af8211c7055e5/consensus/ethash/consensus.go

// SealHash returns the hash of a block prior to it being sealed.
func SealHash(header *types.Header) (hash common.Hash) {
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
	full_enc := enc
	full_enc = append(full_enc, header.MixDigest)
	full_enc = append(full_enc, header.Nonce)
	full_rlp_encoding, _ := rlp.EncodeToBytes(full_enc)
	var rlp_64bit_encoded string
	for i := 0; i < 71; i++ {
		if i*8 <= len(full_rlp_encoding)-8 {
			rlp_64bit_encoded = fmt.Sprintf("%s %d", rlp_64bit_encoded, binary.BigEndian.Uint64(full_rlp_encoding[i*8:i*8+8]))
		} else if i*8 < len(full_rlp_encoding) {
			rlp_64bit_encoded = fmt.Sprintf("%s %d", rlp_64bit_encoded, binary.BigEndian.Uint64(append(full_rlp_encoding[i*8:], make([]byte, 8-len(full_rlp_encoding[i*8:]))...)))
		} else {
			rlp_64bit_encoded = fmt.Sprintf("%s %d", rlp_64bit_encoded, 0)
		}
	}
	fmt.Println(rlp_64bit_encoded)
	fmt.Println(hex.EncodeToString(full_rlp_encoding))
	otherHasher := sha3.NewLegacyKeccak256()
	rlp.Encode(otherHasher, full_enc)
	var hashing common.Hash
	otherHasher.Sum(hashing[:0])
	fmt.Println(hashing)
	otherHasher.Reset()
	otherHasher.Write(full_rlp_encoding)
	otherHasher.Sum(hashing[:0])
	fmt.Println(hashing)
	otherHasher.Reset()
	fmt.Println(binary.BigEndian.Uint64(full_rlp_encoding[len(full_rlp_encoding)-12 : len(full_rlp_encoding)-4]))
	// otherHasher.Write(full_rlp_encoding[len(full_rlp_encoding)-12 : len(full_rlp_encoding)])
	tester := make([]byte, 8)
	binary.BigEndian.PutUint64(tester, binary.BigEndian.Uint64(append(full_rlp_encoding[len(full_rlp_encoding)-4:], make([]byte, 4)...)))
	otherHasher.Write(tester)
	otherHasher.Sum(hashing[:0])
	fmt.Println(hashing)
	otherHasher.Reset()
	otherHasher.Write(full_rlp_encoding[len(full_rlp_encoding)-4:])
	otherHasher.Sum(hashing[:0])
	fmt.Println(hashing)
	otherHasher.Reset()
	ha_encoding, _ := rlp.EncodeToBytes(enc)
	otherHasher.Write(ha_encoding)
	otherHasher.Sum(hashing[:0])
	fmt.Println(hashing)

	rlp.Encode(hasher, enc)
	hasher.Sum(hash[:0])
	return hash
}
