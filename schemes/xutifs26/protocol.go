package xutifs26

import (
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"foldaudit/schemes/benchcore"
)

type Protocol struct {
	M, N, S int
	alpha   *big.Int
	SRSG1   []*bn256.G1
	G2      *bn256.G2
	AlphaG2 *bn256.G2
}

type StoredFile struct {
	FileID []byte
	Blocks []benchcore.Poly
	Tags   []*bn256.G1
	Tree   *benchcore.MerkleTree
	Root   []byte
}

type StoredBatch struct {
	Files []StoredFile
	Roots [][]byte
}

type Challenge struct {
	Indices []int
	Coeffs  []*big.Int
	R       *big.Int
	Seed    []byte
}

type TagOpening struct {
	Index int
	Tag   *bn256.G1
	Path  benchcore.MerkleProof
}

type FileProof struct {
	Value *big.Int
	W     *bn256.G1
	Tags  []TagOpening
}

type Proof struct {
	Files []FileProof
}

func NewProtocol(m, n, s int) *Protocol {
	alpha := benchcore.Scalar("xutifs26/alpha", 0)
	srs := make([]*bn256.G1, s)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, alpha)
	}
	return &Protocol{
		M:       m,
		N:       n,
		S:       s,
		alpha:   alpha,
		SRSG1:   srs,
		G2:      benchcore.G2Base(benchcore.One()),
		AlphaG2: benchcore.G2Base(alpha),
	}
}

func (p *Protocol) Store(data [][][]*big.Int) (*StoredBatch, error) {
	if len(data) != p.M {
		return nil, fmt.Errorf("expected %d files", p.M)
	}
	out := &StoredBatch{Files: make([]StoredFile, p.M), Roots: make([][]byte, p.M)}
	for i := 0; i < p.M; i++ {
		if len(data[i]) != p.N {
			return nil, fmt.Errorf("file %d: expected %d blocks", i, p.N)
		}
		file := StoredFile{FileID: []byte(fmt.Sprintf("file-%d", i)), Blocks: make([]benchcore.Poly, p.N), Tags: make([]*bn256.G1, p.N)}
		leaves := make([][]byte, p.N)
		for j := 0; j < p.N; j++ {
			if len(data[i][j]) != p.S {
				return nil, fmt.Errorf("file %d block %d: expected %d sectors", i, j, p.S)
			}
			file.Blocks[j] = benchcore.NewPoly(data[i][j])
			file.Tags[j] = benchcore.CommitG1(p.SRSG1, file.Blocks[j])
			leaves[j] = xuLeaf(file.Tags[j])
		}
		tree, err := benchcore.NewMerkleTree(leaves)
		if err != nil {
			return nil, err
		}
		file.Tree = tree
		file.Root = benchcore.CloneBytes(tree.Root)
		out.Files[i] = file
		out.Roots[i] = benchcore.CloneBytes(tree.Root)
	}
	return out, nil
}

func (p *Protocol) TagVerify(stored *StoredBatch) bool {
	if stored == nil || len(stored.Files) != p.M || len(stored.Roots) != p.M {
		return false
	}
	for i, file := range stored.Files {
		if len(file.Blocks) != p.N || len(file.Tags) != p.N {
			return false
		}
		leaves := make([][]byte, p.N)
		for j := 0; j < p.N; j++ {
			recomputed := benchcore.CommitG1(p.SRSG1, file.Blocks[j])
			if !benchcore.G1Eq(recomputed, file.Tags[j]) {
				return false
			}
			leaves[j] = xuLeaf(recomputed)
		}
		tree, err := benchcore.NewMerkleTree(leaves)
		if err != nil || string(tree.Root) != string(stored.Roots[i]) {
			return false
		}
	}
	return true
}

func (p *Protocol) Challenge(c int) Challenge {
	return p.ChallengeFromSeed([]byte("xutifs26:commit-reveal:default"), c)
}

func (p *Protocol) ChallengeFromSeed(seed []byte, c int) Challenge {
	if c > p.N {
		c = p.N
	}
	indices := uniqueIndices("xutifs26:challenge:index", seed, c, p.N)
	coeffs := make([]*big.Int, c)
	for i := 0; i < c; i++ {
		coeffs[i] = benchcore.ScalarFromBytes("xutifs26:challenge:coeff", seed, benchcore.IntBytes(i))
	}
	return Challenge{
		Indices: indices,
		Coeffs:  coeffs,
		R:       benchcore.ScalarFromBytes("xutifs26:challenge:r", seed, benchcore.IntBytes(c)),
		Seed:    append([]byte(nil), seed...),
	}
}

func (p *Protocol) Prove(stored *StoredBatch, chal Challenge) (*Proof, error) {
	proof := &Proof{Files: make([]FileProof, len(stored.Files))}
	for i, file := range stored.Files {
		agg := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
		openings := make([]TagOpening, len(chal.Indices))
		for pos, index := range chal.Indices {
			agg = agg.Add(file.Blocks[index].Scale(chal.Coeffs[pos]))
			path, err := file.Tree.Proof(index)
			if err != nil {
				return nil, err
			}
			openings[pos] = TagOpening{Index: index, Tag: file.Tags[index], Path: path}
		}
		value := agg.Eval(chal.R)
		wpoly, rem := agg.SubConstant(value).DivLinear(chal.R)
		if rem.Sign() != 0 {
			return nil, fmt.Errorf("nonzero quotient remainder")
		}
		proof.Files[i] = FileProof{Value: value, W: benchcore.CommitG1(p.SRSG1, wpoly), Tags: openings}
	}
	return proof, nil
}

func (p *Protocol) Verify(stored *StoredBatch, chal Challenge, proof *Proof) bool {
	if stored == nil || proof == nil || len(proof.Files) != len(stored.Files) {
		return false
	}
	sigmaGlobal := benchcore.G1Zero()
	valueGlobal := benchcore.Zero()
	wGlobal := benchcore.G1Zero()
	for i, fp := range proof.Files {
		if len(fp.Tags) != len(chal.Indices) {
			return false
		}
		for pos, opening := range fp.Tags {
			if opening.Index != chal.Indices[pos] || !benchcore.VerifyMerkle(xuLeaf(opening.Tag), stored.Roots[i], opening.Path) {
				return false
			}
			sigmaGlobal = benchcore.G1Add(sigmaGlobal, benchcore.G1Mul(opening.Tag, chal.Coeffs[pos]))
		}
		valueGlobal = benchcore.Add(valueGlobal, fp.Value)
		wGlobal = benchcore.G1Add(wGlobal, fp.W)
	}
	left := benchcore.G1Add(sigmaGlobal, benchcore.G1Neg(benchcore.G1Base(valueGlobal)))
	alphaMinusR := benchcore.G2Add(p.AlphaG2, benchcore.G2Neg(benchcore.G2Base(chal.R)))
	return benchcore.PairingEqual(left, p.G2, wGlobal, alphaMinusR)
}

func xuLeaf(tag *bn256.G1) []byte {
	return benchcore.HashBytes("xutifs26:leaf", tag.Marshal())
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
