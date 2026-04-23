package pdpbatch

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"
)

const DefaultPrimeModulus uint64 = 2_305_843_009_213_693_951

type AuthMode string

const (
	AuthModeSP AuthMode = "sp"
	AuthModeMP AuthMode = "mp"
)

type ProtocolConfig struct {
	NumFiles         int
	ChunksPerFile    int
	SectorsPerChunk  int
	ChallengedChunks int
	PrimeModulus     uint64
	FieldBytes       int
	GroupBytes       int
	HashBytes        int
	RNGSeed          int64
}

func DefaultProtocolConfig() ProtocolConfig {
	return ProtocolConfig{
		NumFiles:         4,
		ChunksPerFile:    64,
		SectorsPerChunk:  8,
		ChallengedChunks: 8,
		PrimeModulus:     DefaultPrimeModulus,
		FieldBytes:       32,
		GroupBytes:       48,
		HashBytes:        32,
		RNGSeed:          7,
	}
}

func (c ProtocolConfig) Validate() error {
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
	if c.PrimeModulus <= 2 {
		return errors.New("prime modulus must be greater than two")
	}
	if c.FieldBytes <= 0 || c.GroupBytes <= 0 || c.HashBytes <= 0 {
		return errors.New("byte-size parameters must be positive")
	}
	return nil
}

type StoredFile struct {
	Sectors     [][]uint64
	Polynomials []Polynomial
	Tags        []GroupElement
	MerkleTree  *MerkleTree
}

type StoredBatch struct {
	Files []StoredFile
	Roots [][]byte
}

type Challenge struct {
	Indices          []int
	Coefficients     map[int]uint64
	EvaluationPoints []uint64
	Nonce            string
}

func (c Challenge) ToPublicDict() map[string]any {
	return map[string]any{
		"indices":           c.Indices,
		"coefficients":      c.Coefficients,
		"evaluation_points": c.EvaluationPoints,
		"nonce":             c.Nonce,
	}
}

type AuthPayload struct {
	Tags         map[int]GroupElement
	SingleProofs map[int]SingleProof
	MultiProof   *MultiProof
}

type FileProof struct {
	Auth   AuthPayload
	B      GroupElement
	YTilde uint64
	R      GroupElement
}

type AuditProof struct {
	AuthMode   AuthMode
	FileProofs []FileProof
	Cq         GroupElement
	Cqr        GroupElement
	VTildeQ    uint64
	RQ         GroupElement
	PiBatch    GroupElement
}

type BatchPDPProtocol struct {
	Config  ProtocolConfig
	Counter *OperationCounter
	Field   *PrimeField

	rng     *rand.Rand
	backend *AlgebraicKZGBackend
	g       GroupElement
}

func Setup(config *ProtocolConfig) (*BatchPDPProtocol, error) {
	cfg := DefaultProtocolConfig()
	if config != nil {
		cfg = *config
	}
	return NewBatchPDPProtocol(cfg)
}

func NewBatchPDPProtocol(config ProtocolConfig) (*BatchPDPProtocol, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	counter := &OperationCounter{}
	field, err := NewPrimeField(config.PrimeModulus, counter)
	if err != nil {
		return nil, err
	}

	rng := rand.New(rand.NewSource(config.RNGSeed))
	tau := field.Random(rng, true)
	backend := NewAlgebraicKZGBackend(field, tau, counter)

	return &BatchPDPProtocol{
		Config:  config,
		Counter: counter,
		Field:   field,
		rng:     rng,
		backend: backend,
		g:       backend.Generator(),
	}, nil
}

func (p *BatchPDPProtocol) RandomFileBatch() [][][]uint64 {
	dataset := make([][][]uint64, p.Config.NumFiles)
	for i := 0; i < p.Config.NumFiles; i++ {
		fileChunks := make([][]uint64, p.Config.ChunksPerFile)
		for j := 0; j < p.Config.ChunksPerFile; j++ {
			sectors := make([]uint64, p.Config.SectorsPerChunk)
			for k := 0; k < p.Config.SectorsPerChunk; k++ {
				sectors[k] = p.Field.Random(p.rng, false)
			}
			fileChunks[j] = sectors
		}
		dataset[i] = fileChunks
	}
	return dataset
}

func (p *BatchPDPProtocol) chunkPolynomial(sectors []uint64) Polynomial {
	return NewPolynomial(sectors, p.Field)
}

func (p *BatchPDPProtocol) merkleLeaf(fileIndex, chunkIndex int, tag GroupElement) []byte {
	return stableHashBytes(p.Counter, "tag-leaf", fileIndex, chunkIndex, tag.Serialize())
}

func (p *BatchPDPProtocol) aggregatePolynomial(storedFile StoredFile, challenge *Challenge) (Polynomial, error) {
	poly := NewPolynomial([]uint64{0}, p.Field)
	for _, j := range challenge.Indices {
		if j < 0 || j >= len(storedFile.Polynomials) {
			return Polynomial{}, fmt.Errorf("challenge index %d out of range", j)
		}
		coefficient, ok := challenge.Coefficients[j]
		if !ok {
			return Polynomial{}, fmt.Errorf("missing challenge coefficient for index %d", j)
		}
		poly = poly.Add(storedFile.Polynomials[j].Scale(coefficient))
	}
	return poly, nil
}

func (p *BatchPDPProtocol) aggregateTag(storedFile StoredFile, challenge *Challenge) (GroupElement, error) {
	result := p.backend.Identity()
	for _, j := range challenge.Indices {
		if j < 0 || j >= len(storedFile.Tags) {
			return GroupElement{}, fmt.Errorf("challenge index %d out of range", j)
		}
		coefficient, ok := challenge.Coefficients[j]
		if !ok {
			return GroupElement{}, fmt.Errorf("missing challenge coefficient for index %d", j)
		}
		result = result.Mul(storedFile.Tags[j].Pow(coefficient))
	}
	return result, nil
}

func (p *BatchPDPProtocol) buildAuthPayload(storedFile StoredFile, challenge *Challenge, authMode AuthMode) (AuthPayload, error) {
	tags := make(map[int]GroupElement, len(challenge.Indices))
	for _, j := range challenge.Indices {
		if j < 0 || j >= len(storedFile.Tags) {
			return AuthPayload{}, fmt.Errorf("challenge index %d out of range", j)
		}
		tags[j] = storedFile.Tags[j]
	}

	switch authMode {
	case AuthModeSP:
		singleProofs := make(map[int]SingleProof, len(challenge.Indices))
		for _, j := range challenge.Indices {
			proof, err := storedFile.MerkleTree.SingleProof(j)
			if err != nil {
				return AuthPayload{}, err
			}
			singleProofs[j] = proof
		}
		return AuthPayload{Tags: tags, SingleProofs: singleProofs}, nil
	case AuthModeMP:
		proof, err := storedFile.MerkleTree.MultiProof(challenge.Indices)
		if err != nil {
			return AuthPayload{}, err
		}
		return AuthPayload{Tags: tags, MultiProof: &proof}, nil
	default:
		return AuthPayload{}, fmt.Errorf("unsupported auth mode %q", authMode)
	}
}

func (p *BatchPDPProtocol) fiatShamirAlpha(
	challenge *Challenge,
	roots [][]byte,
	fileProofs []FileProof,
	Cq GroupElement,
	Cqr GroupElement,
	fileIndex int,
) uint64 {
	bundle := transcriptBundle(fileProofs)
	return hashToField(p.Field, p.Counter, "alpha", challenge.ToPublicDict(), roots, bundle, Cq, Cqr, fileIndex)
}

func (p *BatchPDPProtocol) fiatShamirZ(
	challenge *Challenge,
	roots [][]byte,
	fileProofs []FileProof,
	Cq GroupElement,
	Cqr GroupElement,
	CQ GroupElement,
) uint64 {
	bundle := transcriptBundle(fileProofs)
	return hashToField(p.Field, p.Counter, "z", challenge.ToPublicDict(), roots, bundle, Cq, Cqr, CQ)
}

func (p *BatchPDPProtocol) Store(dataset [][][]uint64) (*StoredBatch, error) {
	if len(dataset) != p.Config.NumFiles {
		return nil, fmt.Errorf("expected %d files, got %d", p.Config.NumFiles, len(dataset))
	}

	storedFiles := make([]StoredFile, 0, len(dataset))
	roots := make([][]byte, 0, len(dataset))

	for i, fileChunks := range dataset {
		if len(fileChunks) != p.Config.ChunksPerFile {
			return nil, fmt.Errorf("file %d: expected %d chunks, got %d", i, p.Config.ChunksPerFile, len(fileChunks))
		}

		polynomials := make([]Polynomial, 0, len(fileChunks))
		tags := make([]GroupElement, 0, len(fileChunks))
		leaves := make([][]byte, 0, len(fileChunks))
		sectorsCopy := make([][]uint64, 0, len(fileChunks))

		for j, sectors := range fileChunks {
			if len(sectors) != p.Config.SectorsPerChunk {
				return nil, fmt.Errorf("file %d chunk %d: expected %d sectors, got %d", i, j, p.Config.SectorsPerChunk, len(sectors))
			}
			sectorCopy := make([]uint64, len(sectors))
			for k, sector := range sectors {
				sectorCopy[k] = p.Field.Normalize(sector)
			}

			poly := p.chunkPolynomial(sectorCopy)
			tag := p.backend.CommitPolynomial(poly)
			leaf := p.merkleLeaf(i, j, tag)

			sectorsCopy = append(sectorsCopy, sectorCopy)
			polynomials = append(polynomials, poly)
			tags = append(tags, tag)
			leaves = append(leaves, leaf)
		}

		tree, err := NewMerkleTree(leaves, p.Counter, nil)
		if err != nil {
			return nil, err
		}
		storedFiles = append(storedFiles, StoredFile{
			Sectors:     sectorsCopy,
			Polynomials: polynomials,
			Tags:        tags,
			MerkleTree:  tree,
		})
		roots = append(roots, cloneBytes(tree.Root))
	}

	return &StoredBatch{Files: storedFiles, Roots: roots}, nil
}

func (p *BatchPDPProtocol) Challenge() *Challenge {
	perm := p.rng.Perm(p.Config.ChunksPerFile)
	indices := append([]int(nil), perm[:p.Config.ChallengedChunks]...)
	sort.Ints(indices)

	coefficients := make(map[int]uint64, len(indices))
	for _, j := range indices {
		coefficients[j] = p.Field.Random(p.rng, true)
	}

	evaluationPoints := make([]uint64, p.Config.NumFiles)
	for i := range evaluationPoints {
		evaluationPoints[i] = p.Field.Random(p.rng, false)
	}

	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	nonce := make([]byte, 16)
	for i := range nonce {
		nonce[i] = alphabet[p.rng.Intn(len(alphabet))]
	}

	return &Challenge{
		Indices:          indices,
		Coefficients:     coefficients,
		EvaluationPoints: evaluationPoints,
		Nonce:            string(nonce),
	}
}

func (p *BatchPDPProtocol) ProofGen(storedBatch *StoredBatch, challenge *Challenge, authMode AuthMode) (*AuditProof, error) {
	if err := p.validateStoredBatch(storedBatch); err != nil {
		return nil, err
	}
	if err := p.validateChallenge(challenge); err != nil {
		return nil, err
	}

	fileProofs := make([]FileProof, 0, len(storedBatch.Files))
	fiPolys := make([]Polynomial, 0, len(storedBatch.Files))
	wiPolys := make([]Polynomial, 0, len(storedBatch.Files))
	var sumRiWiTau uint64

	for i, storedFile := range storedBatch.Files {
		ri := challenge.EvaluationPoints[i]

		fi, err := p.aggregatePolynomial(storedFile, challenge)
		if err != nil {
			return nil, err
		}
		bi, err := p.aggregateTag(storedFile, challenge)
		if err != nil {
			return nil, err
		}
		yi := fi.Evaluate(ri)

		muI := p.Field.Random(p.rng, false)
		yTildeI := p.Field.Add(yi, muI)
		Ri := p.backend.CommitScalar(muI)

		auth, err := p.buildAuthPayload(storedFile, challenge, authMode)
		if err != nil {
			return nil, err
		}

		wi, remainder := fi.SubtractConstant(yi).DivideByLinear(ri)
		if remainder != 0 {
			return nil, fmt.Errorf("quotient remainder non-zero for file %d", i)
		}

		wiTau := wi.Evaluate(p.backend.Tau)
		sumRiWiTau = p.Field.Add(sumRiWiTau, p.Field.Mul(ri, wiTau))

		fiPolys = append(fiPolys, fi)
		wiPolys = append(wiPolys, wi)
		fileProofs = append(fileProofs, FileProof{Auth: auth, B: bi, YTilde: yTildeI, R: Ri})
	}

	qPoly := NewPolynomial([]uint64{0}, p.Field)
	for _, wi := range wiPolys {
		qPoly = qPoly.Add(wi)
	}

	Cq := p.backend.CommitPolynomial(qPoly)
	Cqr := p.backend.CommitScalar(sumRiWiTau)

	alphas := make([]uint64, p.Config.NumFiles)
	for i := 0; i < p.Config.NumFiles; i++ {
		alphas[i] = p.fiatShamirAlpha(challenge, storedBatch.Roots, fileProofs, Cq, Cqr, i)
	}

	QPoly := qPoly
	CQ := Cq
	for i, alpha := range alphas {
		QPoly = QPoly.Add(fiPolys[i].Scale(alpha))
		CQ = CQ.Mul(fileProofs[i].B.Pow(alpha))
	}

	z := p.fiatShamirZ(challenge, storedBatch.Roots, fileProofs, Cq, Cqr, CQ)
	VQ := QPoly.Evaluate(z)

	eta := p.Field.Random(p.rng, false)
	VTildeQ := p.Field.Add(VQ, eta)
	RQ := p.backend.CommitScalar(eta)

	piPoly, remainder := QPoly.SubtractConstant(VQ).DivideByLinear(z)
	if remainder != 0 {
		return nil, errors.New("opening quotient remainder non-zero")
	}
	piBatch := p.backend.CommitPolynomial(piPoly)

	return &AuditProof{
		AuthMode:   authMode,
		FileProofs: fileProofs,
		Cq:         Cq,
		Cqr:        Cqr,
		VTildeQ:    VTildeQ,
		RQ:         RQ,
		PiBatch:    piBatch,
	}, nil
}

func (p *BatchPDPProtocol) verifyAuth(fileIndex int, root []byte, fileProof FileProof, challenge *Challenge, authMode AuthMode) bool {
	leafHashes := make(map[int][]byte, len(challenge.Indices))
	for _, j := range challenge.Indices {
		tag, ok := fileProof.Auth.Tags[j]
		if !ok {
			return false
		}
		leafHashes[j] = p.merkleLeaf(fileIndex, j, tag)
	}

	switch authMode {
	case AuthModeSP:
		if fileProof.Auth.SingleProofs == nil {
			return false
		}
		for _, j := range challenge.Indices {
			proof, ok := fileProof.Auth.SingleProofs[j]
			if !ok || !VerifySingle(leafHashes[j], proof, root, p.Counter) {
				return false
			}
		}
	case AuthModeMP:
		if fileProof.Auth.MultiProof == nil {
			return false
		}
		if !VerifyMulti(leafHashes, *fileProof.Auth.MultiProof, root, p.Counter) {
			return false
		}
	default:
		return false
	}

	bHat := p.backend.Identity()
	for _, j := range challenge.Indices {
		tag, ok := fileProof.Auth.Tags[j]
		if !ok {
			return false
		}
		coefficient, ok := challenge.Coefficients[j]
		if !ok {
			return false
		}
		bHat = bHat.Mul(tag.Pow(coefficient))
	}
	return bHat.Exponent == fileProof.B.Exponent
}

func (p *BatchPDPProtocol) Verify(storedBatch *StoredBatch, challenge *Challenge, proof *AuditProof) bool {
	if p.validateStoredBatch(storedBatch) != nil || p.validateChallenge(challenge) != nil || proof == nil {
		return false
	}
	if len(proof.FileProofs) != p.Config.NumFiles {
		return false
	}

	for i := 0; i < p.Config.NumFiles; i++ {
		if !p.verifyAuth(i, storedBatch.Roots[i], proof.FileProofs[i], challenge, proof.AuthMode) {
			return false
		}
	}

	A := p.backend.Identity()
	for _, fp := range proof.FileProofs {
		term := fp.B.Mul(fp.R).Mul(p.g.Pow(p.Field.Neg(fp.YTilde)))
		A = A.Mul(term)
	}

	if p.backend.Pairing(A.Mul(proof.Cqr), 1) != p.backend.Pairing(proof.Cq, p.backend.Tau) {
		return false
	}

	alphas := make([]uint64, p.Config.NumFiles)
	for i := 0; i < p.Config.NumFiles; i++ {
		alphas[i] = p.fiatShamirAlpha(challenge, storedBatch.Roots, proof.FileProofs, proof.Cq, proof.Cqr, i)
	}

	CQ := proof.Cq
	for i, alpha := range alphas {
		CQ = CQ.Mul(proof.FileProofs[i].B.Pow(alpha))
	}

	z := p.fiatShamirZ(challenge, storedBatch.Roots, proof.FileProofs, proof.Cq, proof.Cqr, CQ)
	lhs := CQ.
		Mul(proof.RQ).
		Mul(p.g.Pow(p.Field.Neg(proof.VTildeQ))).
		Mul(proof.PiBatch.Pow(z))

	return p.backend.Pairing(lhs, 1) == p.backend.Pairing(proof.PiBatch, p.backend.Tau)
}

func (p *BatchPDPProtocol) CloneStoredBatch(storedBatch *StoredBatch) *StoredBatch {
	clonedFiles := make([]StoredFile, len(storedBatch.Files))
	for i, storedFile := range storedBatch.Files {
		sectors := make([][]uint64, len(storedFile.Sectors))
		for j, chunk := range storedFile.Sectors {
			sectors[j] = append([]uint64(nil), chunk...)
		}

		polynomials := make([]Polynomial, len(storedFile.Polynomials))
		for j, poly := range storedFile.Polynomials {
			polynomials[j] = NewPolynomial(poly.Coefficients(), p.Field)
		}

		tags := append([]GroupElement(nil), storedFile.Tags...)
		clonedFiles[i] = StoredFile{
			Sectors:     sectors,
			Polynomials: polynomials,
			Tags:        tags,
			MerkleTree:  storedFile.MerkleTree,
		}
	}

	roots := make([][]byte, len(storedBatch.Roots))
	for i, root := range storedBatch.Roots {
		roots[i] = cloneBytes(root)
	}
	return &StoredBatch{Files: clonedFiles, Roots: roots}
}

func (p *BatchPDPProtocol) TamperChallengedSector(storedBatch *StoredBatch, challenge *Challenge) error {
	if len(challenge.Indices) == 0 {
		return errors.New("challenge has no indices")
	}
	if len(storedBatch.Files) == 0 || len(storedBatch.Files[0].Sectors) == 0 {
		return errors.New("stored batch is empty")
	}

	j := challenge.Indices[0]
	if j < 0 || j >= len(storedBatch.Files[0].Sectors) || len(storedBatch.Files[0].Sectors[j]) == 0 {
		return fmt.Errorf("challenge index %d out of range", j)
	}
	storedBatch.Files[0].Sectors[j][0] = p.Field.Add(storedBatch.Files[0].Sectors[j][0], 1)
	storedBatch.Files[0].Polynomials[j] = p.chunkPolynomial(storedBatch.Files[0].Sectors[j])
	return nil
}

type RoundResult struct {
	Proof    *AuditProof
	TimingMS map[string]float64
	Ops      map[string]map[string]int64
}

func (p *BatchPDPProtocol) MeasureRound(storedBatch *StoredBatch, challenge *Challenge, authMode AuthMode) (*RoundResult, error) {
	before := p.Counter.Snapshot()
	startProof := time.Now()
	proof, err := p.ProofGen(storedBatch, challenge, authMode)
	if err != nil {
		return nil, err
	}
	proofgenMS := float64(time.Since(startProof).Nanoseconds()) / 1_000_000

	middle := p.Counter.Snapshot()
	startVerify := time.Now()
	accepted := p.Verify(storedBatch, challenge, proof)
	verifyMS := float64(time.Since(startVerify).Nanoseconds()) / 1_000_000
	after := p.Counter.Snapshot()
	if !accepted {
		return nil, errors.New("honest proof should verify")
	}

	return &RoundResult{
		Proof: proof,
		TimingMS: map[string]float64{
			"proofgen": math.Round(proofgenMS*1_000_000) / 1_000_000,
			"verify":   math.Round(verifyMS*1_000_000) / 1_000_000,
		},
		Ops: map[string]map[string]int64{
			"proofgen": DiffCounters(middle, before),
			"verify":   DiffCounters(after, middle),
		},
	}, nil
}

func (p *BatchPDPProtocol) SizeReport(challenge *Challenge, proof *AuditProof) map[string]int {
	indexBytes := max(1, int(math.Ceil(math.Log2(float64(p.Config.ChunksPerFile))/8)))
	challengeBytes := len(challenge.Indices)*indexBytes +
		len(challenge.Indices)*p.Config.FieldBytes +
		p.Config.NumFiles*p.Config.FieldBytes

	storeBytes := p.Config.NumFiles*p.Config.ChunksPerFile*p.Config.SectorsPerChunk*p.Config.FieldBytes +
		p.Config.NumFiles*p.Config.ChunksPerFile*p.Config.GroupBytes +
		p.Config.NumFiles*p.Config.HashBytes

	authHashNodes := 0
	for _, fp := range proof.FileProofs {
		if proof.AuthMode == AuthModeSP {
			for _, sp := range fp.Auth.SingleProofs {
				authHashNodes += len(sp.Siblings)
			}
		} else if fp.Auth.MultiProof != nil {
			authHashNodes += fp.Auth.MultiProof.NodeCount()
		}
	}

	proofBytes := p.Config.NumFiles*len(challenge.Indices)*p.Config.GroupBytes +
		p.Config.NumFiles*2*p.Config.GroupBytes +
		p.Config.NumFiles*p.Config.FieldBytes +
		authHashNodes*p.Config.HashBytes +
		4*p.Config.GroupBytes +
		2*p.Config.FieldBytes

	return map[string]int{
		"store_bytes":     storeBytes,
		"challenge_bytes": challengeBytes,
		"proof_bytes":     proofBytes,
		"auth_hash_nodes": authHashNodes,
	}
}

func (p *BatchPDPProtocol) ConfigDict() map[string]any {
	return map[string]any{
		"num_files":         p.Config.NumFiles,
		"chunks_per_file":   p.Config.ChunksPerFile,
		"sectors_per_chunk": p.Config.SectorsPerChunk,
		"challenged_chunks": p.Config.ChallengedChunks,
		"prime_modulus":     p.Config.PrimeModulus,
		"field_bytes":       p.Config.FieldBytes,
		"group_bytes":       p.Config.GroupBytes,
		"hash_bytes":        p.Config.HashBytes,
		"rng_seed":          p.Config.RNGSeed,
	}
}

func (p *BatchPDPProtocol) validateStoredBatch(storedBatch *StoredBatch) error {
	if storedBatch == nil {
		return errors.New("stored batch is nil")
	}
	if len(storedBatch.Files) != p.Config.NumFiles {
		return fmt.Errorf("expected %d stored files, got %d", p.Config.NumFiles, len(storedBatch.Files))
	}
	if len(storedBatch.Roots) != p.Config.NumFiles {
		return fmt.Errorf("expected %d merkle roots, got %d", p.Config.NumFiles, len(storedBatch.Roots))
	}
	for i, storedFile := range storedBatch.Files {
		if len(storedFile.Polynomials) != p.Config.ChunksPerFile || len(storedFile.Tags) != p.Config.ChunksPerFile {
			return fmt.Errorf("stored file %d has inconsistent chunk metadata", i)
		}
		if storedFile.MerkleTree == nil {
			return fmt.Errorf("stored file %d has no merkle tree", i)
		}
	}
	return nil
}

func (p *BatchPDPProtocol) validateChallenge(challenge *Challenge) error {
	if challenge == nil {
		return errors.New("challenge is nil")
	}
	if len(challenge.Indices) == 0 {
		return errors.New("challenge has no indices")
	}
	if len(challenge.EvaluationPoints) != p.Config.NumFiles {
		return fmt.Errorf("expected %d evaluation points, got %d", p.Config.NumFiles, len(challenge.EvaluationPoints))
	}
	seen := make(map[int]struct{}, len(challenge.Indices))
	for _, index := range challenge.Indices {
		if index < 0 || index >= p.Config.ChunksPerFile {
			return fmt.Errorf("challenge index %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			return fmt.Errorf("duplicate challenge index %d", index)
		}
		if _, ok := challenge.Coefficients[index]; !ok {
			return fmt.Errorf("missing challenge coefficient for index %d", index)
		}
		seen[index] = struct{}{}
	}
	return nil
}

type fileTranscript struct {
	B      GroupElement `json:"b"`
	YTilde uint64       `json:"y_tilde"`
	R      GroupElement `json:"R"`
}

func transcriptBundle(fileProofs []FileProof) []fileTranscript {
	bundle := make([]fileTranscript, len(fileProofs))
	for i, proof := range fileProofs {
		bundle[i] = fileTranscript{B: proof.B, YTilde: proof.YTilde, R: proof.R}
	}
	return bundle
}
