package zhangtpds23

import (
	"bytes"
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"foldaudit/schemes/benchcore"
)

type Protocol struct {
	M, N, S int
	x       *big.Int
	alpha   *big.Int
	SRSG1   []*bn256.G1
	G2      *bn256.G2
	V       *bn256.G2
	U       *bn256.G2
}

type StoredFile struct {
	FileID []byte
	Blocks []benchcore.Poly
	Tags   []*bn256.G1
}

type StoredBatch struct {
	Files []StoredFile
}

type Challenge struct {
	Indices [][]int
	Coeffs  [][]*big.Int
	Points  []*big.Int
	Gamma   *big.Int
	Z       *big.Int
	Seed    []byte
}

type Proof struct {
	SigmaPrime *bn256.G1
	W          *bn256.G1
	WPrime     *bn256.G1
	E          *big.Int
}

func NewProtocol(m, n, s int) *Protocol {
	x := benchcore.Scalar("zhangtpds23/x", 0)
	alpha := benchcore.Scalar("zhangtpds23/alpha", 0)
	srs := make([]*bn256.G1, s)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, alpha)
	}
	g2 := benchcore.G2Base(benchcore.One())
	v := benchcore.G2Base(x)
	u := benchcore.G2Base(benchcore.Mul(alpha, x))
	return &Protocol{M: m, N: n, S: s, x: x, alpha: alpha, SRSG1: srs, G2: g2, V: v, U: u}
}

func (p *Protocol) Store(data [][][]*big.Int) (*StoredBatch, error) {
	if len(data) != p.M {
		return nil, fmt.Errorf("expected %d files", p.M)
	}
	out := &StoredBatch{Files: make([]StoredFile, p.M)}
	for i := 0; i < p.M; i++ {
		if len(data[i]) != p.N {
			return nil, fmt.Errorf("file %d: expected %d blocks", i, p.N)
		}
		file := StoredFile{FileID: []byte(fmt.Sprintf("file-%d", i)), Blocks: make([]benchcore.Poly, p.N), Tags: make([]*bn256.G1, p.N)}
		for j := 0; j < p.N; j++ {
			if len(data[i][j]) != p.S {
				return nil, fmt.Errorf("file %d block %d: expected %d sectors", i, j, p.S)
			}
			file.Blocks[j] = benchcore.NewPoly(data[i][j])
			body := benchcore.G1Add(hashIndex(file.FileID, j), p.ownerCommit(file.Blocks[j]))
			file.Tags[j] = benchcore.G1Mul(body, p.x)
		}
		out.Files[i] = file
	}
	return out, nil
}

func (p *Protocol) ownerCommit(poly benchcore.Poly) *bn256.G1 {
	if p.alpha == nil {
		panic("zhangtpds23: missing data-owner trapdoor for Store")
	}
	return benchcore.G1Base(poly.Eval(p.alpha))
}

func (p *Protocol) TagVerify(stored *StoredBatch) bool {
	if stored == nil || len(stored.Files) != p.M {
		return false
	}
	for _, file := range stored.Files {
		if len(file.Blocks) != p.N || len(file.Tags) != p.N {
			return false
		}
		for j := range file.Blocks {
			body := benchcore.G1Add(hashIndex(file.FileID, j), benchcore.CommitG1(p.SRSG1, file.Blocks[j]))
			if !benchcore.PairingEqual(file.Tags[j], p.G2, body, p.V) {
				return false
			}
		}
	}
	return true
}

func (p *Protocol) Challenge(c int) Challenge {
	return p.ChallengeFromSeed(mustRandomBytes("zhangtpds23 challenge seed"), c)
}

func (p *Protocol) ChallengeFromSeed(seed []byte, c int) Challenge {
	if c > p.N {
		c = p.N
	}
	indices := make([][]int, p.M)
	coeffs := make([][]*big.Int, p.M)
	for i := range coeffs {
		indices[i] = uniqueIndices("zhangtpds23:challenge:index", seedFor(seed, i), c, p.N)
		coeffs[i] = make([]*big.Int, c)
		for j := range coeffs[i] {
			coeffs[i][j] = benchcore.ScalarFromBytes("zhangtpds23:challenge:coeff", seed, benchcore.IntBytes(i), benchcore.IntBytes(j))
		}
	}
	points := make([]*big.Int, p.M)
	for i := range points {
		points[i] = benchcore.ScalarFromBytes("zhangtpds23:challenge:r", seed, benchcore.IntBytes(i))
	}
	z := benchcore.ScalarFromBytes("zhangtpds23:challenge:z", seed, benchcore.IntBytes(c))
	return Challenge{Indices: indices, Coeffs: coeffs, Points: points, Gamma: benchcore.ScalarFromBytes("zhangtpds23:challenge:gamma", seed), Z: z, Seed: append([]byte(nil), seed...)}
}

func (p *Protocol) Prove(stored *StoredBatch, chal Challenge) (*Proof, error) {
	if stored == nil || len(stored.Files) != p.M {
		return nil, fmt.Errorf("stored batch mismatch")
	}
	betas := p.betas(chal)
	sigmaPrime := benchcore.G1Zero()
	E := benchcore.Zero()
	F := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
	sumBetaDiff := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
	for i, file := range stored.Files {
		agg := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
		tagAgg := benchcore.G1Zero()
		if len(chal.Indices[i]) != len(chal.Coeffs[i]) {
			return nil, fmt.Errorf("file %d challenge dimension mismatch", i)
		}
		for pos, index := range chal.Indices[i] {
			agg = agg.Add(file.Blocks[index].Scale(chal.Coeffs[i][pos]))
			tagAgg = benchcore.G1Add(tagAgg, benchcore.G1Mul(file.Tags[index], chal.Coeffs[i][pos]))
		}
		S := agg.Eval(chal.Points[i])
		diff := agg.SubConstant(S)
		ztExcept := zExcept(chal.Points, i)
		F = F.Add(ztExcept.Mul(diff).Scale(benchcore.Pow(chal.Gamma, i)))
		sumBetaDiff = sumBetaDiff.Add(diff.Scale(betas[i]))
		sigmaPrime = benchcore.G1Add(sigmaPrime, benchcore.G1Mul(tagAgg, betas[i]))
		E = benchcore.Add(E, benchcore.Mul(betas[i], S))
	}
	Hb, rem, err := F.Div(benchcore.ZPoly(chal.Points))
	if err != nil {
		return nil, err
	}
	if !(len(rem.Coeffs) == 1 && rem.Coeffs[0].Sign() == 0) {
		return nil, fmt.Errorf("batch polynomial is not divisible by Z_T")
	}
	ztAtZ := benchcore.ZPoly(chal.Points).Eval(chal.Z)
	L := sumBetaDiff.Sub(Hb.Scale(ztAtZ))
	LQuotient, LRem := L.DivLinear(chal.Z)
	if LRem.Sign() != 0 {
		return nil, fmt.Errorf("folded quotient polynomial has nonzero remainder")
	}
	return &Proof{
		SigmaPrime: sigmaPrime,
		W:          benchcore.CommitG1(p.SRSG1, Hb),
		WPrime:     benchcore.CommitG1(p.SRSG1, LQuotient),
		E:          E,
	}, nil
}

func (p *Protocol) Verify(stored *StoredBatch, chal Challenge, proof *Proof) bool {
	if stored == nil || proof == nil || len(stored.Files) != p.M {
		return false
	}
	betas := p.betas(chal)
	zeta := benchcore.G1Zero()
	for i, file := range stored.Files {
		if len(chal.Indices[i]) != len(chal.Coeffs[i]) {
			return false
		}
		for pos, index := range chal.Indices[i] {
			term := benchcore.G1Mul(hashIndex(file.FileID, index), chal.Coeffs[i][pos])
			zeta = benchcore.G1Add(zeta, benchcore.G1Mul(term, betas[i]))
		}
	}
	ztAtZ := benchcore.ZPoly(chal.Points).Eval(chal.Z)
	psi := benchcore.G1Add(benchcore.G1Base(benchcore.Neg(proof.E)), benchcore.G1Mul(proof.W, benchcore.Neg(ztAtZ)))
	uMinusZV := benchcore.G2Add(p.U, benchcore.G2Mul(p.V, benchcore.Neg(chal.Z)))
	return benchcore.PairingProductIsOne(
		[]*bn256.G1{proof.SigmaPrime, psi, benchcore.G1Neg(zeta), benchcore.G1Neg(proof.WPrime)},
		[]*bn256.G2{p.G2, p.V, p.V, uMinusZV},
	)
}

func (p *Protocol) betas(chal Challenge) []*big.Int {
	out := make([]*big.Int, p.M)
	for i := range out {
		out[i] = benchcore.Mul(benchcore.Pow(chal.Gamma, i), zExcept(chal.Points, i).Eval(chal.Z))
	}
	return out
}

func zExcept(points []*big.Int, skip int) benchcore.Poly {
	subset := make([]*big.Int, 0, len(points)-1)
	for i, point := range points {
		if i != skip {
			subset = append(subset, point)
		}
	}
	return benchcore.ZPoly(subset)
}

func hashIndex(fileID []byte, index int) *bn256.G1 {
	return benchcore.HashToG1Bytes("zhangtpds23:H", fileID, benchcore.IntBytes(index))
}

func mustRandomBytes(context string) []byte {
	out, err := benchcore.RandomBytes(nil, 32)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", context, err))
	}
	return out
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

func seedFor(seed []byte, index int) []byte {
	var out bytes.Buffer
	benchcore.WriteFramed(&out, seed)
	benchcore.WriteFramed(&out, benchcore.IntBytes(index))
	return out.Bytes()
}
