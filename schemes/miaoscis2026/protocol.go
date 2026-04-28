package miaoscis2026

import (
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"foldaudit/schemes/benchcore"
)

type Protocol struct {
	N int
	x *big.Int
	U *bn256.G1
	G *bn256.G2
	Y *bn256.G2
}

type File struct {
	FID      []byte
	Keywords []string
	Blocks   []*big.Int
	Aux      []string
	HF       *bn256.G1
	Omega    *bn256.G1
	Sigmas   []*bn256.G1
}

type StoredData struct {
	Files []File
}

type Challenge struct {
	Keywords []string
	Indices  []int
	Coeffs   [][]*big.Int
}

type Proof struct {
	TAuth *bn256.G1
	Mu1   *big.Int
	R     *bn256.G1
}

func NewProtocol(n int) *Protocol {
	x := benchcore.Scalar("miaoscis2026/x", 0)
	return &Protocol{
		N: n,
		x: x,
		U: benchcore.G1Base(benchcore.One()),
		G: benchcore.G2Base(benchcore.One()),
		Y: benchcore.G2Base(x),
	}
}

func (p *Protocol) Store(files []struct {
	FID      string
	Keywords []string
	Blocks   []*big.Int
}) (*StoredData, error) {
	out := &StoredData{Files: make([]File, len(files))}
	for i, input := range files {
		if len(input.Blocks) != p.N {
			return nil, fmt.Errorf("file %d: expected %d blocks", i, p.N)
		}
		f := File{
			FID:      []byte(input.FID),
			Keywords: append([]string(nil), input.Keywords...),
			Blocks:   make([]*big.Int, p.N),
			Aux:      make([]string, p.N),
			Sigmas:   make([]*bn256.G1, p.N),
		}
		f.HF = p.keywordProduct(f.Keywords)
		base := benchcore.G1Add(f.HF, h2FID(f.FID))
		f.Omega = benchcore.G1Mul(base, benchcore.Neg(p.x))
		for j, block := range input.Blocks {
			f.Blocks[j] = benchcore.Normalize(block)
			f.Aux[j] = fmt.Sprintf("au-%d-%d", i, j)
			body := benchcore.G1Add(base, h3Aux(f.Aux[j]))
			body = benchcore.G1Add(body, benchcore.G1Mul(p.U, f.Blocks[j]))
			f.Sigmas[j] = benchcore.G1Mul(body, p.x)
		}
		out.Files[i] = f
	}
	return out, nil
}

func (p *Protocol) Challenge(keywords []string, c int, files int) Challenge {
	if c > p.N {
		c = p.N
	}
	indices := make([]int, c)
	for i := range indices {
		indices[i] = i
	}
	coeffs := make([][]*big.Int, files)
	for i := range coeffs {
		coeffs[i] = make([]*big.Int, c)
		for j := range coeffs[i] {
			coeffs[i][j] = benchcore.Scalar(fmt.Sprintf("miaoscis2026/chal/%d", i), j)
		}
	}
	return Challenge{Keywords: append([]string(nil), keywords...), Indices: indices, Coeffs: coeffs}
}

func (p *Protocol) Prove(stored *StoredData, chal Challenge) (*Proof, error) {
	matched := matchingFiles(stored.Files, chal.Keywords)
	tAuth := benchcore.G1Zero()
	mu := benchcore.Zero()
	for _, fileIndex := range matched {
		file := stored.Files[fileIndex]
		for pos, blockIndex := range chal.Indices {
			coeff := chal.Coeffs[fileIndex][pos]
			tAuth = benchcore.G1Add(tAuth, benchcore.G1Mul(file.Sigmas[blockIndex], coeff))
			mu = benchcore.Add(mu, benchcore.Mul(coeff, file.Blocks[blockIndex]))
		}
	}
	r := benchcore.Scalar("miaoscis2026/mask/r", len(matched)+len(chal.Indices))
	R := benchcore.G1Base(r)
	h := challengeHash(chal.Keywords, R)
	mu1 := benchcore.Sub(mu, benchcore.Mul(r, h))
	return &Proof{TAuth: tAuth, Mu1: mu1, R: R}, nil
}

func (p *Protocol) Verify(stored *StoredData, chal Challenge, proof *Proof) bool {
	if stored == nil || proof == nil || len(chal.Coeffs) < len(stored.Files) {
		return false
	}
	matched := matchingFiles(stored.Files, chal.Keywords)
	left := proof.TAuth
	right := benchcore.G1Zero()
	for _, fileIndex := range matched {
		file := stored.Files[fileIndex]
		sum := benchcore.Zero()
		for pos, blockIndex := range chal.Indices {
			coeff := chal.Coeffs[fileIndex][pos]
			sum = benchcore.Add(sum, coeff)
			right = benchcore.G1Add(right, benchcore.G1Mul(h3Aux(file.Aux[blockIndex]), coeff))
		}
		left = benchcore.G1Add(left, benchcore.G1Mul(file.Omega, sum))
	}
	right = benchcore.G1Add(right, benchcore.G1Mul(p.U, proof.Mu1))
	right = benchcore.G1Add(right, benchcore.G1Mul(proof.R, challengeHash(chal.Keywords, proof.R)))
	return benchcore.PairingEqual(left, p.G, right, p.Y)
}

func (p *Protocol) keywordProduct(keywords []string) *bn256.G1 {
	out := benchcore.G1Zero()
	for _, keyword := range keywords {
		out = benchcore.G1Add(out, h1Keyword(keyword))
	}
	return out
}

func matchingFiles(files []File, keywords []string) []int {
	var out []int
	for i, file := range files {
		if containsAll(file.Keywords, keywords) {
			out = append(out, i)
		}
	}
	return out
}

func containsAll(have []string, want []string) bool {
	set := make(map[string]struct{}, len(have))
	for _, value := range have {
		set[value] = struct{}{}
	}
	for _, value := range want {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func h1Keyword(keyword string) *bn256.G1 {
	return benchcore.HashToG1Bytes("miaoscis2026:H1", []byte(keyword))
}

func h2FID(fid []byte) *bn256.G1 {
	return benchcore.HashToG1Bytes("miaoscis2026:H2", fid)
}

func h3Aux(aux string) *bn256.G1 {
	return benchcore.HashToG1Bytes("miaoscis2026:H3", []byte(aux))
}

func challengeHash(keywords []string, r *bn256.G1) *big.Int {
	parts := make([][]byte, 0, len(keywords)+1)
	for _, keyword := range keywords {
		parts = append(parts, []byte(keyword))
	}
	parts = append(parts, r.Marshal())
	return benchcore.ScalarFromBytes("miaoscis2026:h1", parts...)
}
