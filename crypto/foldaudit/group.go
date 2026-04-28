package foldaudit

import (
	"bytes"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

var order = bn256.Order

func g1BaseMult(k *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarBaseMult(normalizeScalar(k))
}

func g2BaseMult(k *big.Int) *bn256.G2 {
	return new(bn256.G2).ScalarBaseMult(normalizeScalar(k))
}

func g1Identity() *bn256.G1 {
	return g1BaseMult(scalarZero())
}

func g1Add(a, b *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Add(a, b)
}

func g1Neg(a *bn256.G1) *bn256.G1 {
	return new(bn256.G1).Neg(a)
}

func g1ScalarMult(a *bn256.G1, k *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarMult(a, normalizeScalar(k))
}

func g1Equal(a, b *bn256.G1) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func cloneG1(a *bn256.G1) *bn256.G1 {
	if a == nil {
		return nil
	}
	return new(bn256.G1).Set(a)
}

func cloneG2(a *bn256.G2) *bn256.G2 {
	if a == nil {
		return nil
	}
	return new(bn256.G2).Set(a)
}

func pairingEqual(left *bn256.G1, leftG2 *bn256.G2, right *bn256.G1, rightG2 *bn256.G2) bool {
	return bn256.PairingCheck(
		[]*bn256.G1{left, g1Neg(right)},
		[]*bn256.G2{leftG2, rightG2},
	)
}

