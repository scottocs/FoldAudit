package benchcore

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

var Order = new(big.Int).Set(bn256.Order)

func Normalize(x *big.Int) *big.Int {
	if x == nil {
		return new(big.Int)
	}
	out := new(big.Int).Mod(new(big.Int).Set(x), Order)
	if out.Sign() < 0 {
		out.Add(out, Order)
	}
	return out
}

func Scalar(label string, i int) *big.Int {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], uint64(i))
	digest := sha256.Sum256(append([]byte(label), idx[:]...))
	x := Normalize(new(big.Int).SetBytes(digest[:]))
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return x
}
