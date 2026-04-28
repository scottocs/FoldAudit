package foldaudit

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"

	"foldaudit/schemes/benchcore"
)

type Config struct {
	NumFiles         int
	ChunksPerFile    int
	SectorsPerChunk  int
	ChallengedChunks int
}

func DefaultConfig() Config {
	return Config{
		NumFiles:         4,
		ChunksPerFile:    64,
		SectorsPerChunk:  8,
		ChallengedChunks: 8,
	}
}

func (c Config) Validate() error {
	if c.NumFiles <= 0 {
		return errors.New("num files must be positive")
	}
	if c.ChunksPerFile <= 0 {
		return errors.New("chunks per file must be positive")
	}
	if c.SectorsPerChunk <= 0 {
		return errors.New("sectors per chunk must be positive")
	}
	if c.ChallengedChunks <= 0 || c.ChallengedChunks > c.ChunksPerFile {
		return errors.New("challenged chunks must be in [1, chunks per file]")
	}
	return nil
}

type PublicParams struct {
	SRSG1 []*bn256.G1
	G2    *bn256.G2
	TauG2 *bn256.G2
}

type Protocol struct {
	Config Config
	PP     PublicParams

	tau  *big.Int
	rand io.Reader
}

func Setup(config Config, reader io.Reader) (*Protocol, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if reader == nil {
		reader = rand.Reader
	}

	tau, err := randomScalar(reader, true)
	if err != nil {
		return nil, err
	}

	srs := make([]*bn256.G1, config.SectorsPerChunk)
	power := benchcore.One()
	for i := range srs {
		srs[i] = benchcore.G1Base(power)
		power = benchcore.Mul(power, tau)
	}

	return &Protocol{
		Config: config,
		PP: PublicParams{
			SRSG1: srs,
			G2:    benchcore.G2Base(benchcore.One()),
			TauG2: benchcore.G2Base(tau),
		},
		tau:  benchcore.Normalize(tau),
		rand: reader,
	}, nil
}

func NewProtocol(config Config, reader io.Reader) (*Protocol, error) {
	return Setup(config, reader)
}

type StoredFile struct {
	FileID      []byte
	Sectors     [][]*big.Int
	Polynomials []benchcore.Poly
	Tags        []*bn256.G1
	Tree        *benchcore.MerkleTree
	Root        []byte
}

type StoredBatch struct {
	Files []StoredFile
	Roots [][]byte
}

type Challenge struct {
	Indices          []int
	Coefficients     [][]*big.Int
	EvaluationPoints []*big.Int
	Nonce            []byte
}

type TagProof struct {
	Index int
	Tag   *bn256.G1
	Path  benchcore.MerkleProof
}

type SchnorrProof struct {
	A *bn256.G1
	Z *big.Int
}

type FileProof struct {
	Auth   []TagProof
	YTilde *big.Int
	R      *bn256.G1
	Cw     *bn256.G1
	B      *bn256.G1
}

type AuditProof struct {
	FileProofs []FileProof
	PiR        []SchnorrProof
}

func (p *Protocol) RandomDataset() ([][][]*big.Int, error) {
	data := make([][][]*big.Int, p.Config.NumFiles)
	for i := range data {
		data[i] = make([][]*big.Int, p.Config.ChunksPerFile)
		for j := range data[i] {
			data[i][j] = make([]*big.Int, p.Config.SectorsPerChunk)
			for k := range data[i][j] {
				x, err := randomScalar(p.rand, false)
				if err != nil {
					return nil, err
				}
				data[i][j][k] = x
			}
		}
	}
	return data, nil
}

func (p *Protocol) Store(dataset [][][]*big.Int) (*StoredBatch, error) {
	if len(dataset) != p.Config.NumFiles {
		return nil, fmt.Errorf("expected %d files, got %d", p.Config.NumFiles, len(dataset))
	}

	files := make([]StoredFile, len(dataset))
	roots := make([][]byte, len(dataset))
	for i, chunks := range dataset {
		if len(chunks) != p.Config.ChunksPerFile {
			return nil, fmt.Errorf("file %d: expected %d chunks, got %d", i, p.Config.ChunksPerFile, len(chunks))
		}

		fileID := []byte(fmt.Sprintf("file-%d", i))
		sectors := make([][]*big.Int, len(chunks))
		polys := make([]benchcore.Poly, len(chunks))
		tags := make([]*bn256.G1, len(chunks))
		leaves := make([][]byte, len(chunks))
		for j, chunk := range chunks {
			if len(chunk) != p.Config.SectorsPerChunk {
				return nil, fmt.Errorf("file %d chunk %d: expected %d sectors, got %d", i, j, p.Config.SectorsPerChunk, len(chunk))
			}
			sectors[j] = cloneScalars(chunk)
			polys[j] = benchcore.NewPoly(sectors[j])
			tags[j] = p.CommitPolynomial(polys[j])
			leaves[j] = merkleLeaf(fileID, j, tags[j])
		}

		tree, err := benchcore.NewMerkleTree(leaves)
		if err != nil {
			return nil, err
		}
		files[i] = StoredFile{
			FileID:      benchcore.CloneBytes(fileID),
			Sectors:     sectors,
			Polynomials: polys,
			Tags:        tags,
			Tree:        tree,
			Root:        benchcore.CloneBytes(tree.Root),
		}
		roots[i] = benchcore.CloneBytes(tree.Root)
	}

	return &StoredBatch{Files: files, Roots: roots}, nil
}

func (p *Protocol) Challenge() (*Challenge, error) {
	indices, err := p.sampleIndices()
	if err != nil {
		return nil, err
	}

	coefficients := make([][]*big.Int, p.Config.NumFiles)
	for i := range coefficients {
		coefficients[i] = make([]*big.Int, len(indices))
		for j := range indices {
			coefficients[i][j], err = randomScalar(p.rand, true)
			if err != nil {
				return nil, err
			}
		}
	}

	points := make([]*big.Int, p.Config.NumFiles)
	for i := range points {
		points[i], err = randomScalar(p.rand, false)
		if err != nil {
			return nil, err
		}
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(p.rand, nonce); err != nil {
		return nil, err
	}

	return &Challenge{
		Indices:          indices,
		Coefficients:     coefficients,
		EvaluationPoints: points,
		Nonce:            nonce,
	}, nil
}

func (p *Protocol) ProofGen(stored *StoredBatch, chal *Challenge) (*AuditProof, error) {
	if err := p.validateStoredBatch(stored); err != nil {
		return nil, err
	}
	if err := p.validateChallenge(chal); err != nil {
		return nil, err
	}

	fileProofs := make([]FileProof, p.Config.NumFiles)
	masks := make([]*big.Int, p.Config.NumFiles)
	for i := range stored.Files {
		fi, err := p.aggregatePolynomial(stored.Files[i], chal, i)
		if err != nil {
			return nil, err
		}
		bi := p.CommitPolynomial(fi)
		yi := fi.Eval(chal.EvaluationPoints[i])

		mu, err := randomScalar(p.rand, false)
		if err != nil {
			return nil, err
		}
		masks[i] = mu
		yTilde := benchcore.Add(yi, mu)
		Ri := benchcore.G1Base(mu)

		wi, remainder := fi.SubConstant(yi).DivLinear(chal.EvaluationPoints[i])
		if remainder.Sign() != 0 {
			return nil, fmt.Errorf("file %d quotient has nonzero remainder", i)
		}
		Cwi := p.CommitPolynomial(wi)

		auth, err := p.authPaths(stored.Files[i], chal)
		if err != nil {
			return nil, err
		}
		fileProofs[i] = FileProof{
			Auth:   auth,
			YTilde: yTilde,
			R:      Ri,
			Cw:     Cwi,
			B:      bi,
		}
	}

	piR, err := p.schnorrMaskProofs(stored.Roots, chal, fileProofs, masks)
	if err != nil {
		return nil, err
	}
	return &AuditProof{FileProofs: fileProofs, PiR: piR}, nil
}

func (p *Protocol) Verify(stored *StoredBatch, chal *Challenge, proof *AuditProof) bool {
	if p.validateStoredBatch(stored) != nil || p.validateChallenge(chal) != nil || proof == nil {
		return false
	}
	if len(proof.FileProofs) != p.Config.NumFiles || len(proof.PiR) != p.Config.NumFiles {
		return false
	}

	for i, fp := range proof.FileProofs {
		if !p.verifyAuth(stored.Files[i], stored.Roots[i], fp, chal) {
			return false
		}
		bHat, ok := p.aggregateProofTag(fp, chal, i)
		if !ok || !benchcore.G1Eq(bHat, fp.B) {
			return false
		}
	}

	if !p.verifySchnorrMaskProofs(stored.Roots, chal, proof) {
		return false
	}

	rho := p.fiatShamirRho(stored.Roots, chal, proof)
	left := benchcore.G1Zero()
	right := benchcore.G1Zero()
	rhoPower := benchcore.One()
	for i, fp := range proof.FileProofs {
		term := benchcore.G1Add(fp.B, fp.R)
		term = benchcore.G1Add(term, benchcore.G1Base(benchcore.Neg(fp.YTilde)))
		term = benchcore.G1Add(term, benchcore.G1Mul(fp.Cw, chal.EvaluationPoints[i]))
		left = benchcore.G1Add(left, benchcore.G1Mul(term, rhoPower))
		right = benchcore.G1Add(right, benchcore.G1Mul(fp.Cw, rhoPower))
		rhoPower = benchcore.Mul(rhoPower, rho)
	}
	return benchcore.PairingEqual(left, p.PP.G2, right, p.PP.TauG2)
}

func (p *Protocol) CommitPolynomial(poly benchcore.Poly) *bn256.G1 {
	return benchcore.CommitG1(p.PP.SRSG1, poly)
}

func (p *Protocol) sampleIndices() ([]int, error) {
	selected := make(map[int]struct{}, p.Config.ChallengedChunks)
	for len(selected) < p.Config.ChallengedChunks {
		x, err := rand.Int(p.rand, big.NewInt(int64(p.Config.ChunksPerFile)))
		if err != nil {
			return nil, err
		}
		selected[int(x.Int64())] = struct{}{}
	}
	indices := make([]int, 0, len(selected))
	for index := range selected {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices, nil
}

func (p *Protocol) aggregatePolynomial(file StoredFile, chal *Challenge, fileIndex int) (benchcore.Poly, error) {
	out := benchcore.NewPoly([]*big.Int{benchcore.Zero()})
	for pos, chunkIndex := range chal.Indices {
		if chunkIndex < 0 || chunkIndex >= len(file.Polynomials) {
			return benchcore.Poly{}, fmt.Errorf("challenge index %d out of range", chunkIndex)
		}
		out = out.Add(file.Polynomials[chunkIndex].Scale(chal.Coefficients[fileIndex][pos]))
	}
	return out, nil
}

func (p *Protocol) authPaths(file StoredFile, chal *Challenge) ([]TagProof, error) {
	out := make([]TagProof, len(chal.Indices))
	for pos, chunkIndex := range chal.Indices {
		path, err := file.Tree.Proof(chunkIndex)
		if err != nil {
			return nil, err
		}
		out[pos] = TagProof{
			Index: chunkIndex,
			Tag:   cloneG1(file.Tags[chunkIndex]),
			Path:  path,
		}
	}
	return out, nil
}

func (p *Protocol) verifyAuth(file StoredFile, root []byte, fp FileProof, chal *Challenge) bool {
	if len(fp.Auth) != len(chal.Indices) {
		return false
	}
	for pos, chunkIndex := range chal.Indices {
		auth := fp.Auth[pos]
		if auth.Index != chunkIndex || auth.Tag == nil {
			return false
		}
		leaf := merkleLeaf(file.FileID, chunkIndex, auth.Tag)
		if !benchcore.VerifyMerkle(leaf, root, auth.Path) {
			return false
		}
	}
	return true
}

func (p *Protocol) aggregateProofTag(fp FileProof, chal *Challenge, fileIndex int) (*bn256.G1, bool) {
	if len(fp.Auth) != len(chal.Indices) {
		return nil, false
	}
	out := benchcore.G1Zero()
	for pos, auth := range fp.Auth {
		if auth.Index != chal.Indices[pos] || auth.Tag == nil {
			return nil, false
		}
		out = benchcore.G1Add(out, benchcore.G1Mul(auth.Tag, chal.Coefficients[fileIndex][pos]))
	}
	return out, true
}

func (p *Protocol) schnorrMaskProofs(roots [][]byte, chal *Challenge, fps []FileProof, masks []*big.Int) ([]SchnorrProof, error) {
	stmt := maskStatementBytes(roots, chal, fps)
	proofs := make([]SchnorrProof, len(fps))
	for i := range fps {
		a, err := randomScalar(p.rand, false)
		if err != nil {
			return nil, err
		}
		A := benchcore.G1Base(a)
		c := benchcore.ScalarFromBytes("foldaudit:mask-pok", stmt, benchcore.IntBytes(i), g1Bytes(A))
		z := benchcore.Add(a, benchcore.Mul(c, masks[i]))
		proofs[i] = SchnorrProof{A: A, Z: z}
	}
	return proofs, nil
}

func (p *Protocol) verifySchnorrMaskProofs(roots [][]byte, chal *Challenge, proof *AuditProof) bool {
	stmt := maskStatementBytes(roots, chal, proof.FileProofs)
	for i, pi := range proof.PiR {
		if pi.A == nil || pi.Z == nil {
			return false
		}
		c := benchcore.ScalarFromBytes("foldaudit:mask-pok", stmt, benchcore.IntBytes(i), g1Bytes(pi.A))
		left := benchcore.G1Base(pi.Z)
		right := benchcore.G1Add(pi.A, benchcore.G1Mul(proof.FileProofs[i].R, c))
		if !benchcore.G1Eq(left, right) {
			return false
		}
	}
	return true
}

func (p *Protocol) fiatShamirRho(roots [][]byte, chal *Challenge, proof *AuditProof) *big.Int {
	parts := [][]byte{challengeBytes(chal), rootsBytes(roots), fileProofStatementBytes(proof.FileProofs), schnorrProofBytes(proof.PiR)}
	return benchcore.ScalarFromBytes("foldaudit:fold", parts...)
}

func (p *Protocol) validateStoredBatch(stored *StoredBatch) error {
	if stored == nil {
		return errors.New("stored batch is nil")
	}
	if len(stored.Files) != p.Config.NumFiles || len(stored.Roots) != p.Config.NumFiles {
		return errors.New("stored batch file/root count mismatch")
	}
	for i, file := range stored.Files {
		if len(file.Polynomials) != p.Config.ChunksPerFile || len(file.Tags) != p.Config.ChunksPerFile {
			return fmt.Errorf("file %d chunk metadata mismatch", i)
		}
		if file.Tree == nil {
			return fmt.Errorf("file %d merkle tree is nil", i)
		}
	}
	return nil
}

func (p *Protocol) validateChallenge(chal *Challenge) error {
	if chal == nil {
		return errors.New("challenge is nil")
	}
	if len(chal.Indices) != p.Config.ChallengedChunks {
		return errors.New("challenge index count mismatch")
	}
	if len(chal.Coefficients) != p.Config.NumFiles || len(chal.EvaluationPoints) != p.Config.NumFiles {
		return errors.New("challenge file dimension mismatch")
	}
	last := -1
	for _, index := range chal.Indices {
		if index <= last || index < 0 || index >= p.Config.ChunksPerFile {
			return fmt.Errorf("invalid challenge index %d", index)
		}
		last = index
	}
	for i := range chal.Coefficients {
		if len(chal.Coefficients[i]) != len(chal.Indices) {
			return fmt.Errorf("challenge coefficient count mismatch for file %d", i)
		}
	}
	return nil
}

func merkleLeaf(fileID []byte, index int, tag *bn256.G1) []byte {
	return benchcore.HashBytes("foldaudit:merkle:leaf", fileID, benchcore.IntBytes(index), g1Bytes(tag))
}

func randomScalar(reader io.Reader, nonZero bool) (*big.Int, error) {
	for {
		x, err := rand.Int(reader, benchcore.Order)
		if err != nil {
			return nil, err
		}
		x = benchcore.Normalize(x)
		if !nonZero || x.Sign() != 0 {
			return x, nil
		}
	}
}

func cloneScalars(values []*big.Int) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = benchcore.Normalize(value)
	}
	return out
}

func cloneG1(point *bn256.G1) *bn256.G1 {
	if point == nil {
		return nil
	}
	return new(bn256.G1).Set(point)
}

func g1Bytes(point *bn256.G1) []byte {
	if point == nil {
		return nil
	}
	return point.Marshal()
}
