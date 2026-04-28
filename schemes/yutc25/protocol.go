package yutc25

import (
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"foldaudit/schemes/benchcore"
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

type StoredBatch struct {
	Files []*StoredData
	Roots [][]byte
}

type Challenge struct {
	Indices []int
	Coeffs  []*big.Int
	Z       *big.Int
	K1      []byte
	K2      []byte
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

type BatchChallenge struct {
	FileChallenges []Challenge
}

type BatchProof struct {
	Proofs []*Proof
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

func (p *Protocol) StoreBatch(files [][][]*big.Int) (*StoredBatch, error) {
	out := &StoredBatch{Files: make([]*StoredData, len(files)), Roots: make([][]byte, len(files))}
	for i, blocks := range files {
		stored, err := p.Store(blocks)
		if err != nil {
			return nil, fmt.Errorf("file %d: %w", i, err)
		}
		out.Files[i] = stored
		out.Roots[i] = benchcore.CloneBytes(stored.Root)
	}
	return out, nil
}

func (p *Protocol) Challenge(c int) Challenge {
	return p.ChallengeFromKeys([]byte("default-k1"), []byte("default-k2"), c)
}

func (p *Protocol) ChallengeFromKeys(k1, k2 []byte, c int) Challenge {
	if c > p.N {
		c = p.N
	}
	indices := uniqueIndices("yutc25:prp", k1, c, p.N)
	coeffs := make([]*big.Int, c)
	for i := 0; i < c; i++ {
		coeffs[i] = benchcore.ScalarFromBytes("yutc25:prf:coeff", k2, benchcore.IntBytes(i))
	}
	return Challenge{
		Indices: indices,
		Coeffs:  coeffs,
		Z:       benchcore.ScalarFromBytes("yutc25:prf:z", k2, benchcore.IntBytes(c)),
		K1:      append([]byte(nil), k1...),
		K2:      append([]byte(nil), k2...),
	}
}

func (p *Protocol) BatchChallenge(files, c int) BatchChallenge {
	out := BatchChallenge{FileChallenges: make([]Challenge, files)}
	for i := range out.FileChallenges {
		out.FileChallenges[i] = p.ChallengeFromKeys(
			[]byte(fmt.Sprintf("batch-k1-%d", i)),
			[]byte(fmt.Sprintf("batch-k2-%d", i)),
			c,
		)
	}
	return out
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

func (p *Protocol) ProveBatch(stored *StoredBatch, chal BatchChallenge) (*BatchProof, error) {
	if stored == nil || len(stored.Files) != len(chal.FileChallenges) {
		return nil, fmt.Errorf("batch dimension mismatch")
	}
	out := &BatchProof{Proofs: make([]*Proof, len(stored.Files))}
	for i := range stored.Files {
		proof, err := p.Prove(stored.Files[i], chal.FileChallenges[i])
		if err != nil {
			return nil, fmt.Errorf("file %d: %w", i, err)
		}
		out.Proofs[i] = proof
	}
	return out, nil
}

func (p *Protocol) VerifyBatch(stored *StoredBatch, chal BatchChallenge, proof *BatchProof) bool {
	if stored == nil || proof == nil || len(stored.Files) != len(chal.FileChallenges) || len(proof.Proofs) != len(stored.Files) {
		return false
	}
	for i := range stored.Files {
		if !p.Verify(stored.Roots[i], chal.FileChallenges[i], proof.Proofs[i]) {
			return false
		}
	}
	return true
}

func yuLeaf(tag *bn256.G1) []byte {
	return benchcore.HashBytes("yutc25:tag-imht", tag.Marshal())
}

func uniqueIndices(label string, seed []byte, c, n int) []int {
	if c > n {
		c = n
	}
	selected := make(map[int]struct{}, c)
	for ctr := 0; len(selected) < c; ctr++ {
		x := benchcore.ScalarFromBytes(label, seed, benchcore.IntBytes(ctr))
		selected[int(new(big.Int).Mod(x, big.NewInt(int64(n))).Int64())] = struct{}{}
	}
	out := make([]int, 0, c)
	for index := range selected {
		out = append(out, index)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}
