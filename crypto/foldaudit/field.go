package foldaudit

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

var fieldOrder = new(big.Int).Set(bn256Order())

func bn256Order() *big.Int {
	return new(big.Int).Set(order)
}

func normalizeScalar(x *big.Int) *big.Int {
	if x == nil {
		return new(big.Int)
	}
	out := new(big.Int).Mod(new(big.Int).Set(x), fieldOrder)
	if out.Sign() < 0 {
		out.Add(out, fieldOrder)
	}
	return out
}

func scalarZero() *big.Int {
	return new(big.Int)
}

func scalarOne() *big.Int {
	return big.NewInt(1)
}

func scalarAdd(a, b *big.Int) *big.Int {
	out := new(big.Int).Add(normalizeScalar(a), normalizeScalar(b))
	out.Mod(out, fieldOrder)
	return out
}

func scalarSub(a, b *big.Int) *big.Int {
	out := new(big.Int).Sub(normalizeScalar(a), normalizeScalar(b))
	out.Mod(out, fieldOrder)
	if out.Sign() < 0 {
		out.Add(out, fieldOrder)
	}
	return out
}

func scalarNeg(a *big.Int) *big.Int {
	if a == nil || a.Sign() == 0 {
		return scalarZero()
	}
	out := new(big.Int).Neg(normalizeScalar(a))
	out.Mod(out, fieldOrder)
	return out
}

func scalarMul(a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(normalizeScalar(a), normalizeScalar(b))
	out.Mod(out, fieldOrder)
	return out
}

func scalarInv(a *big.Int) (*big.Int, error) {
	a = normalizeScalar(a)
	if a.Sign() == 0 {
		return nil, errors.New("zero scalar has no inverse")
	}
	out := new(big.Int).ModInverse(a, fieldOrder)
	if out == nil {
		return nil, errors.New("scalar is not invertible")
	}
	return out, nil
}

func scalarEqual(a, b *big.Int) bool {
	return normalizeScalar(a).Cmp(normalizeScalar(b)) == 0
}

func randomScalar(r io.Reader, nonzero bool) (*big.Int, error) {
	if r == nil {
		r = rand.Reader
	}
	for {
		x, err := rand.Int(r, fieldOrder)
		if err != nil {
			return nil, err
		}
		if !nonzero || x.Sign() != 0 {
			return x, nil
		}
	}
}

func scalarBytes(x *big.Int) []byte {
	x = normalizeScalar(x)
	out := make([]byte, 32)
	xb := x.Bytes()
	copy(out[len(out)-len(xb):], xb)
	return out
}

func cloneScalar(x *big.Int) *big.Int {
	return normalizeScalar(x)
}

