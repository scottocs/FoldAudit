package benchcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
)

func Zero() *big.Int { return new(big.Int) }

func One() *big.Int { return big.NewInt(1) }

func Add(a, b *big.Int) *big.Int {
	out := new(big.Int).Add(Normalize(a), Normalize(b))
	out.Mod(out, Order)
	return out
}

func Sub(a, b *big.Int) *big.Int {
	out := new(big.Int).Sub(Normalize(a), Normalize(b))
	out.Mod(out, Order)
	if out.Sign() < 0 {
		out.Add(out, Order)
	}
	return out
}

func Neg(a *big.Int) *big.Int {
	if a == nil || a.Sign() == 0 {
		return Zero()
	}
	return Sub(Zero(), a)
}

func Mul(a, b *big.Int) *big.Int {
	out := new(big.Int).Mul(Normalize(a), Normalize(b))
	out.Mod(out, Order)
	return out
}

func Inv(a *big.Int) (*big.Int, error) {
	a = Normalize(a)
	if a.Sign() == 0 {
		return nil, errors.New("zero scalar has no inverse")
	}
	out := new(big.Int).ModInverse(a, Order)
	if out == nil {
		return nil, errors.New("scalar is not invertible")
	}
	return out, nil
}

func Pow(a *big.Int, exp int) *big.Int {
	if exp < 0 {
		panic("negative exponent")
	}
	out := One()
	base := Normalize(a)
	for exp > 0 {
		if exp&1 == 1 {
			out = Mul(out, base)
		}
		base = Mul(base, base)
		exp >>= 1
	}
	return out
}

func G1Base(k *big.Int) *bn256.G1 { return new(bn256.G1).ScalarBaseMult(Normalize(k)) }

func G2Base(k *big.Int) *bn256.G2 { return new(bn256.G2).ScalarBaseMult(Normalize(k)) }

func G1Zero() *bn256.G1 { return G1Base(Zero()) }

func G2Zero() *bn256.G2 { return G2Base(Zero()) }

func G1Add(a, b *bn256.G1) *bn256.G1 { return new(bn256.G1).Add(a, b) }

func G2Add(a, b *bn256.G2) *bn256.G2 { return new(bn256.G2).Add(a, b) }

func G1Neg(a *bn256.G1) *bn256.G1 { return new(bn256.G1).Neg(a) }

func G2Neg(a *bn256.G2) *bn256.G2 { return new(bn256.G2).Neg(a) }

func G1Mul(a *bn256.G1, k *big.Int) *bn256.G1 {
	return new(bn256.G1).ScalarMult(a, Normalize(k))
}

func G2Mul(a *bn256.G2, k *big.Int) *bn256.G2 {
	return new(bn256.G2).ScalarMult(a, Normalize(k))
}

func G1Eq(a, b *bn256.G1) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func G2Eq(a, b *bn256.G2) bool {
	if a == nil || b == nil {
		return a == b
	}
	return bytes.Equal(a.Marshal(), b.Marshal())
}

func PairingEqual(left *bn256.G1, leftG2 *bn256.G2, right *bn256.G1, rightG2 *bn256.G2) bool {
	return bn256.PairingCheck([]*bn256.G1{left, G1Neg(right)}, []*bn256.G2{leftG2, rightG2})
}

func PairingProductIsOne(g1s []*bn256.G1, g2s []*bn256.G2) bool {
	return bn256.PairingCheck(g1s, g2s)
}

func HashBytes(label string, parts ...[]byte) []byte {
	h := sha256.New()
	WriteFramed(h, []byte(label))
	for _, part := range parts {
		WriteFramed(h, part)
	}
	return h.Sum(nil)
}

func WriteFramed(dst interface{ Write([]byte) (int, error) }, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = dst.Write(length[:])
	_, _ = dst.Write(value)
}

func ScalarFromBytes(label string, parts ...[]byte) *big.Int {
	x := Normalize(new(big.Int).SetBytes(HashBytes(label, parts...)))
	if x.Sign() == 0 {
		x.SetInt64(1)
	}
	return x
}

func IntBytes(value int) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], uint64(value))
	return out[:]
}

func ScalarBytes(x *big.Int) []byte {
	x = Normalize(x)
	out := make([]byte, 32)
	xb := x.Bytes()
	copy(out[len(out)-len(xb):], xb)
	return out
}

func HashToG1Bytes(label string, parts ...[]byte) *bn256.G1 {
	return G1Base(ScalarFromBytes(label, parts...))
}

type Poly struct {
	Coeffs []*big.Int
}

func NewPoly(coeffs []*big.Int) Poly {
	if len(coeffs) == 0 {
		coeffs = []*big.Int{Zero()}
	}
	out := make([]*big.Int, len(coeffs))
	for i, coeff := range coeffs {
		out[i] = Normalize(coeff)
	}
	p := Poly{Coeffs: out}
	p.Trim()
	return p
}

func (p *Poly) Trim() {
	for len(p.Coeffs) > 1 && p.Coeffs[len(p.Coeffs)-1].Sign() == 0 {
		p.Coeffs = p.Coeffs[:len(p.Coeffs)-1]
	}
}

func (p Poly) Clone() Poly {
	return NewPoly(p.Coeffs)
}

func (p Poly) Degree() int {
	return len(p.Coeffs) - 1
}

func (p Poly) Add(q Poly) Poly {
	size := len(p.Coeffs)
	if len(q.Coeffs) > size {
		size = len(q.Coeffs)
	}
	out := make([]*big.Int, size)
	for i := 0; i < size; i++ {
		a, b := Zero(), Zero()
		if i < len(p.Coeffs) {
			a = p.Coeffs[i]
		}
		if i < len(q.Coeffs) {
			b = q.Coeffs[i]
		}
		out[i] = Add(a, b)
	}
	return NewPoly(out)
}

func (p Poly) Sub(q Poly) Poly {
	return p.Add(q.Scale(Neg(One())))
}

func (p Poly) Scale(k *big.Int) Poly {
	out := make([]*big.Int, len(p.Coeffs))
	for i, coeff := range p.Coeffs {
		out[i] = Mul(coeff, k)
	}
	return NewPoly(out)
}

func (p Poly) Mul(q Poly) Poly {
	out := make([]*big.Int, len(p.Coeffs)+len(q.Coeffs)-1)
	for i := range out {
		out[i] = Zero()
	}
	for i, a := range p.Coeffs {
		for j, b := range q.Coeffs {
			out[i+j] = Add(out[i+j], Mul(a, b))
		}
	}
	return NewPoly(out)
}

func (p Poly) Eval(x *big.Int) *big.Int {
	x = Normalize(x)
	out := Zero()
	for i := len(p.Coeffs) - 1; i >= 0; i-- {
		out = Add(Mul(out, x), p.Coeffs[i])
		if i == 0 {
			break
		}
	}
	return out
}

func (p Poly) SubConstant(c *big.Int) Poly {
	out := p.Clone()
	out.Coeffs[0] = Sub(out.Coeffs[0], c)
	out.Trim()
	return out
}

func (p Poly) DivLinear(root *big.Int) (Poly, *big.Int) {
	root = Normalize(root)
	if len(p.Coeffs) == 1 {
		return NewPoly([]*big.Int{Zero()}), Normalize(p.Coeffs[0])
	}
	q := make([]*big.Int, len(p.Coeffs)-1)
	carry := Normalize(p.Coeffs[len(p.Coeffs)-1])
	for i := len(p.Coeffs) - 2; i >= 0; i-- {
		q[i] = Normalize(carry)
		carry = Add(p.Coeffs[i], Mul(root, carry))
		if i == 0 {
			break
		}
	}
	return NewPoly(q), carry
}

func (p Poly) Div(divisor Poly) (Poly, Poly, error) {
	divisor.Trim()
	if len(divisor.Coeffs) == 0 || (len(divisor.Coeffs) == 1 && divisor.Coeffs[0].Sign() == 0) {
		return Poly{}, Poly{}, errors.New("division by zero polynomial")
	}
	rem := p.Clone()
	if rem.Degree() < divisor.Degree() {
		return NewPoly([]*big.Int{Zero()}), rem, nil
	}
	q := make([]*big.Int, rem.Degree()-divisor.Degree()+1)
	for i := range q {
		q[i] = Zero()
	}
	invLead, err := Inv(divisor.Coeffs[len(divisor.Coeffs)-1])
	if err != nil {
		return Poly{}, Poly{}, err
	}
	for rem.Degree() >= divisor.Degree() && !(len(rem.Coeffs) == 1 && rem.Coeffs[0].Sign() == 0) {
		degDiff := rem.Degree() - divisor.Degree()
		scale := Mul(rem.Coeffs[len(rem.Coeffs)-1], invLead)
		q[degDiff] = scale
		sub := make([]*big.Int, degDiff+len(divisor.Coeffs))
		for i := range sub {
			sub[i] = Zero()
		}
		for i, coeff := range divisor.Coeffs {
			sub[i+degDiff] = Mul(coeff, scale)
		}
		rem = rem.Sub(NewPoly(sub))
	}
	return NewPoly(q), rem, nil
}

func ZPoly(points []*big.Int) Poly {
	out := NewPoly([]*big.Int{One()})
	for _, point := range points {
		out = out.Mul(NewPoly([]*big.Int{Neg(point), One()}))
	}
	return out
}

func CommitG1(srs []*bn256.G1, poly Poly) *bn256.G1 {
	out := G1Zero()
	for i, coeff := range poly.Coeffs {
		if i >= len(srs) {
			panic(fmt.Sprintf("degree %d exceeds SRS length %d", i, len(srs)))
		}
		out = G1Add(out, G1Mul(srs[i], coeff))
	}
	return out
}

type MerkleProof struct {
	Index    int
	Siblings [][]byte
}

type MerkleTree struct {
	LeafCount int
	Levels    [][][]byte
	Root      []byte
}

func NewMerkleTree(leaves [][]byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("empty merkle tree")
	}
	size := 1
	for size < len(leaves) {
		size <<= 1
	}
	level := make([][]byte, size)
	for i := range level {
		if i < len(leaves) {
			level[i] = CloneBytes(leaves[i])
		} else {
			level[i] = HashBytes("benchcore:merkle:pad")
		}
	}
	levels := [][][]byte{level}
	for len(level) > 1 {
		next := make([][]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = HashBytes("benchcore:merkle:node", level[i], level[i+1])
		}
		levels = append(levels, next)
		level = next
	}
	return &MerkleTree{LeafCount: len(leaves), Levels: levels, Root: CloneBytes(levels[len(levels)-1][0])}, nil
}

func (t *MerkleTree) Proof(index int) (MerkleProof, error) {
	if t == nil {
		return MerkleProof{}, errors.New("nil merkle tree")
	}
	if index < 0 || index >= t.LeafCount {
		return MerkleProof{}, fmt.Errorf("leaf %d out of range", index)
	}
	pos := index
	siblings := make([][]byte, 0, len(t.Levels)-1)
	for level := 0; level < len(t.Levels)-1; level++ {
		siblings = append(siblings, CloneBytes(t.Levels[level][pos^1]))
		pos >>= 1
	}
	return MerkleProof{Index: index, Siblings: siblings}, nil
}

func VerifyMerkle(leaf, root []byte, proof MerkleProof) bool {
	current := CloneBytes(leaf)
	pos := proof.Index
	for _, sibling := range proof.Siblings {
		if pos%2 == 0 {
			current = HashBytes("benchcore:merkle:node", current, sibling)
		} else {
			current = HashBytes("benchcore:merkle:node", sibling, current)
		}
		pos >>= 1
	}
	return bytes.Equal(current, root)
}

func CloneBytes(value []byte) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
