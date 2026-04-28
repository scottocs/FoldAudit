package miaoscis2026

import (
	"bytes"
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
	Files         []File
	KeywordRows   map[string]int
	EncryptedRows map[int][]byte
	MatrixSize    int
}

type TrapdoorToken struct {
	Keyword string
	Row     int
	Pad     []byte
}

type Trapdoor struct {
	Tokens []TrapdoorToken
}

type Challenge struct {
	Keywords []string
	Indices  []int
	Coeffs   [][]*big.Int
	Trapdoor Trapdoor
	K1       []byte
	K2       []byte
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
	out := &StoredData{
		Files:         make([]File, len(files)),
		KeywordRows:   make(map[string]int),
		EncryptedRows: make(map[int][]byte),
	}
	keywordSet := make(map[string]struct{})
	for _, input := range files {
		for _, keyword := range input.Keywords {
			keywordSet[keyword] = struct{}{}
		}
	}
	out.MatrixSize = 2*max(len(files), len(keywordSet)) + 1
	row := 0
	for keyword := range keywordSet {
		for {
			candidate := int(new(big.Int).Mod(benchcore.ScalarFromBytes("miaoscis2026:row", []byte(keyword), benchcore.IntBytes(row)), big.NewInt(int64(out.MatrixSize))).Int64())
			if _, used := out.EncryptedRows[candidate]; !used {
				out.KeywordRows[keyword] = candidate
				out.EncryptedRows[candidate] = nil
				break
			}
			row++
		}
	}
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
	for keyword, row := range out.KeywordRows {
		plain := make([]byte, len(out.Files))
		for i, file := range out.Files {
			if containsAll(file.Keywords, []string{keyword}) {
				plain[i] = 1
			}
		}
		pad := rowPad(row, len(plain))
		out.EncryptedRows[row] = xorBytes(plain, pad)
	}
	return out, nil
}

func (p *Protocol) Trapdoor(stored *StoredData, keywords []string) (Trapdoor, error) {
	if stored == nil {
		return Trapdoor{}, fmt.Errorf("stored data is nil")
	}
	tokens := make([]TrapdoorToken, len(keywords))
	for i, keyword := range keywords {
		row, ok := stored.KeywordRows[keyword]
		if !ok {
			return Trapdoor{}, fmt.Errorf("unknown keyword %q", keyword)
		}
		tokens[i] = TrapdoorToken{
			Keyword: keyword,
			Row:     row,
			Pad:     rowPad(row, len(stored.Files)),
		}
	}
	return Trapdoor{Tokens: tokens}, nil
}

func (p *Protocol) Challenge(keywords []string, c int, files int) Challenge {
	k1 := mustRandomBytes("miaoscis2026 challenge k1")
	k2 := mustRandomBytes("miaoscis2026 challenge k2")
	return p.challengeWith(keywords, Trapdoor{}, k1, k2, c, files, p.challengeCoeffs(k2, c, files))
}

func (p *Protocol) ChallengeWithTrapdoor(trap Trapdoor, c int, files int) Challenge {
	keywords := make([]string, len(trap.Tokens))
	for i, token := range trap.Tokens {
		keywords[i] = token.Keyword
	}
	k1 := mustRandomBytes("miaoscis2026 trapdoor challenge k1")
	k2 := mustRandomBytes("miaoscis2026 trapdoor challenge k2")
	return p.challengeWith(keywords, trap, k1, k2, c, files, p.challengeCoeffs(k2, c, files))
}

func (p *Protocol) challengeWith(keywords []string, trap Trapdoor, k1, k2 []byte, c int, files int, coeffs [][]*big.Int) Challenge {
	if c > p.N {
		c = p.N
	}
	return Challenge{
		Keywords: append([]string(nil), keywords...),
		Indices:  uniqueIndices("miaoscis2026:challenge:index", k1, c, p.N),
		Coeffs:   coeffs,
		Trapdoor: trap,
		K1:       append([]byte(nil), k1...),
		K2:       append([]byte(nil), k2...),
	}
}

func (p *Protocol) challengeCoeffs(k2 []byte, c int, files int) [][]*big.Int {
	if c > p.N {
		c = p.N
	}
	coeffs := make([][]*big.Int, files)
	for i := range coeffs {
		coeffs[i] = make([]*big.Int, c)
		for j := range coeffs[i] {
			coeffs[i][j] = benchcore.ScalarFromBytes("miaoscis2026:challenge:coeff", k2, benchcore.IntBytes(i), benchcore.IntBytes(j))
		}
	}
	return coeffs
}

func (p *Protocol) Prove(stored *StoredData, chal Challenge) (*Proof, error) {
	matched := matchedByChallenge(stored, chal)
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
	matched := matchedByChallenge(stored, chal)
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

func mustRandomBytes(context string) []byte {
	out, err := benchcore.RandomBytes(nil, 32)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", context, err))
	}
	return out
}

func challengeHash(keywords []string, r *bn256.G1) *big.Int {
	parts := make([][]byte, 0, len(keywords)+1)
	for _, keyword := range keywords {
		parts = append(parts, []byte(keyword))
	}
	parts = append(parts, r.Marshal())
	return benchcore.ScalarFromBytes("miaoscis2026:h1", parts...)
}

func matchedByChallenge(stored *StoredData, chal Challenge) []int {
	if stored == nil {
		return nil
	}
	if len(chal.Trapdoor.Tokens) == 0 {
		return matchingFiles(stored.Files, chal.Keywords)
	}
	mask := make([]byte, len(stored.Files))
	for i := range mask {
		mask[i] = 1
	}
	for _, token := range chal.Trapdoor.Tokens {
		encrypted, ok := stored.EncryptedRows[token.Row]
		if !ok || len(encrypted) != len(stored.Files) {
			return nil
		}
		row := xorBytes(encrypted, token.Pad)
		for i := range mask {
			mask[i] &= row[i]
		}
	}
	out := make([]int, 0)
	for i, value := range mask {
		if value == 1 {
			out = append(out, i)
		}
	}
	return out
}

func rowPad(row, size int) []byte {
	var out bytes.Buffer
	for out.Len() < size {
		chunk := benchcore.HashBytes("miaoscis2026:row-pad", benchcore.IntBytes(row), benchcore.IntBytes(out.Len()))
		out.Write(chunk)
	}
	return out.Bytes()[:size]
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i%len(b)]
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

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
