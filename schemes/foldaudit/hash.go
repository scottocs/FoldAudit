package foldaudit

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func hashBytes(label string, parts ...[]byte) []byte {
	h := sha256.New()
	writeBytes(hWrite{h}, []byte(label))
	for _, part := range parts {
		writeBytes(hWrite{h}, part)
	}
	return h.Sum(nil)
}

type hWrite struct {
	w interface {
		Write([]byte) (int, error)
	}
}

func writeBytes(dst hWrite, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = dst.w.Write(length[:])
	_, _ = dst.w.Write(value)
}

func hashToScalar(label string, parts ...[]byte) *big.Int {
	digest := hashBytes(label, parts...)
	return normalizeScalar(new(big.Int).SetBytes(digest))
}

func intBytes(value int) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], uint64(value))
	return out[:]
}

func g1Bytes(point *bn256.G1) []byte {
	if point == nil {
		return nil
	}
	return point.Marshal()
}

func g2Bytes(point *bn256.G2) []byte {
	if point == nil {
		return nil
	}
	return point.Marshal()
}

func cloneBytes(value []byte) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
