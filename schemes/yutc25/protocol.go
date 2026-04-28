package yutc25

import (
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"pdp26/schemes/benchcore"
)

type Protocol struct {
	N, S int
	psi  *big.Int
	SRS  []*bn256.G1
}

type StoredData struct {
	Blocks []benchcore.Poly
	Tags   []*bn256.G1
	Tree   *benchcore.MerkleTree
	Root   []byte
}

type Challenge struct {
	Indices []int
	Coeffs  []*big.Int
	Z       *big.Int
}

type TagOpening struct {
	Index int
	Tag   *bn256.G1
	Path  benchcore.MerkleProof
}

type Proof struct {
	Quotient benchcore.Poly
	Openings []TagOpening
	Value    *big.Int
	B        *bn256.G1
}

func NewProtocol(n, s int) *Protocol {
	psi := benchcore.Scalar("yutc25/psi", 0)
	srs := make([]*bn256.G1, s+1)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, psi)
	}
	return &Protocol{N: n, S: s, psi: psi, SRS: srs}
}

func (p *Protocol) Store(blocks [][]*big.Int) (*StoredData, error) {
	if len(blocks) != p.N {
		return nil, fmt.Errorf("expected %d blocks", p.N)
	}
	out := &StoredData{Blocks: make([]benchcore.Poly, p.N), Tags: make([]*bn256.G1, p.N)}
	leaves := make([][]byte, p.N)
	for i, block := range blocks {
		if len(block) != p.S {
			return nil, fmt.Errorf("block %d: expected %d sectors", i, p.S)
		}
		out.Blocks[i] = benchcore.NewPoly(block)
		out.Tags[i] = benchcore.CommitG1(p.SRS, out.Blocks[i])
		leaves[i] = yuLeaf(out.Tags[i])
	}
	tree, err := benchcore.NewMerkleTree(leaves)
	if err != nil {
		return nil, err
	}
	out.Tree = tree
	out.Root = benchcore.CloneBytes(tree.Root)
	return out, nil
}

func (p *Protocol) Challenge(c int) Challenge {
	if c > p.N {
		c = p.N
	}
	indices := make([]int, c)
	coeffs := make([]*big.Int, c)
	for i := 0; i < c; i++ {
		indices[i] = i
		coeffs[i] = benchcore.Scalar("yutc25/chal/coeff", i)
	}
	return Challenge{Indices: indices, Coeffs: coeffs, Z: benchcore.Scalar("yutc25/chal/z", c)}
}

func (p *Protocol) Prove(stored *StoredData, chal Challenge) (*Proof, error) {
	beta := benchcore.Scalar("yutc25/privacy/beta", len(chal.Indices))
	B := benchcore.G1Base(beta)
	eta := benchcore.ScalarFromBytes("yutc25/eta", B.Marshal())

	agg := benchcore.NewPoly([]*big.Int{benchcore.Mul(beta, eta)})
	openings := make([]TagOpening, len(chal.Indices))
	for pos, index := range chal.Indices {
		agg = agg.Add(stored.Blocks[index].Scale(chal.Coeffs[pos]))
		path, err := stored.Tree.Proof(index)
		if err != nil {
			return nil, err
		}
		openings[pos] = TagOpening{Index: index, Tag: stored.Tags[index], Path: path}
	}
	value := agg.Eval(chal.Z)
	quotient, rem := agg.SubConstant(value).DivLinear(chal.Z)
	if rem.Sign() != 0 {
		return nil, fmt.Errorf("nonzero quotient remainder")
	}
	return &Proof{Quotient: quotient, Openings: openings, Value: value, B: B}, nil
}

func (p *Protocol) Verify(root []byte, chal Challenge, proof *Proof) bool {
	if proof == nil || len(proof.Openings) != len(chal.Indices) {
		return false
	}
	left := benchcore.G1Zero()
	for pos, opening := range proof.Openings {
		if opening.Index != chal.Indices[pos] || !benchcore.VerifyMerkle(yuLeaf(opening.Tag), root, opening.Path) {
			return false
		}
		left = benchcore.G1Add(left, benchcore.G1Mul(opening.Tag, chal.Coeffs[pos]))
	}
	eta := benchcore.ScalarFromBytes("yutc25/eta", proof.B.Marshal())
	left = benchcore.G1Add(left, benchcore.G1Mul(proof.B, eta))

	hz := benchcore.CommitG1(p.SRS, proof.Quotient)
	hprf := benchcore.G1Zero()
	for i, coeff := range proof.Quotient.Coeffs {
		hprf = benchcore.G1Add(hprf, benchcore.G1Mul(p.SRS[i+1], coeff))
	}
	right := benchcore.G1Add(hprf, benchcore.G1Mul(hz, benchcore.Neg(chal.Z)))
	right = benchcore.G1Add(right, benchcore.G1Base(proof.Value))
	return benchcore.G1Eq(left, right)
}

func yuLeaf(tag *bn256.G1) []byte {
	return benchcore.HashBytes("yutc25:tag-imht", tag.Marshal())
}
