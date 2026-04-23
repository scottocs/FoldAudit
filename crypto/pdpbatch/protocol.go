package pdpbatch

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"
)

const DefaultPrimeModulus = "52435875175126190479447740508185965837690552500527637822603658699938581184513"

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
	PrimeModulus     string
	FieldBytes       int
	GroupBytes       int
	HashBytes        int
	RNGSeed          int64
}

// DefaultProtocolConfig 返回一组适合本地演示和快速基准测试的默认协议参数。
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

// Validate 检查协议参数是否满足批量 PDP 流程的基本边界条件。
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
	if c.PrimeModulus == "" {
		return errors.New("prime modulus must be set")
	}
	if c.FieldBytes <= 0 || c.GroupBytes <= 0 || c.HashBytes <= 0 {
		return errors.New("byte-size parameters must be positive")
	}
	return nil
}

type StoredFile struct {
	Sectors     [][]Scalar
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
	Coefficients     map[int]Scalar
	EvaluationPoints []Scalar
	Nonce            string
}

// ToPublicDict 将挑战转换为稳定的公开字典，用于 Fiat-Shamir transcript 哈希。
func (c Challenge) ToPublicDict() map[string]any {
	coefficients := make(map[string]string, len(c.Coefficients))
	for index, coefficient := range c.Coefficients {
		coefficients[fmt.Sprint(index)] = scalarHex(coefficient)
	}
	evaluationPoints := make([]string, len(c.EvaluationPoints))
	for i, point := range c.EvaluationPoints {
		evaluationPoints[i] = scalarHex(point)
	}
	return map[string]any{
		"indices":           c.Indices,
		"coefficients":      coefficients,
		"evaluation_points": evaluationPoints,
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
	YTilde Scalar
	R      GroupElement
}

type AuditProof struct {
	AuthMode   AuthMode
	FileProofs []FileProof
	Cq         GroupElement
	Cqr        GroupElement
	VTildeQ    Scalar
	RQ         GroupElement
	PiBatch    GroupElement
}

type BatchPDPProtocol struct {
	Config  ProtocolConfig
	Counter *OperationCounter
	Field   *PrimeField

	rng     *rand.Rand
	backend *CurveKZGBackend
	g       GroupElement
}

// Setup 兼容可选配置入口：为空时使用默认参数，否则按传入配置初始化协议。
func Setup(config *ProtocolConfig) (*BatchPDPProtocol, error) {
	cfg := DefaultProtocolConfig()
	if config != nil {
		cfg = *config
	}
	return NewBatchPDPProtocol(cfg)
}

// NewBatchPDPProtocol 初始化有限域、随机源、KZG 后端和操作计数器。
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
	backend, err := NewCurveKZGBackend(field, config.SectorsPerChunk, rng, counter)
	if err != nil {
		return nil, err
	}

	return &BatchPDPProtocol{
		Config:  config,
		Counter: counter,
		Field:   field,
		rng:     rng,
		backend: backend,
		g:       backend.Generator(),
	}, nil
}

// RandomFileBatch 按当前配置生成一批随机文件数据，结构为 文件-分块-扇区。
func (p *BatchPDPProtocol) RandomFileBatch() [][][]Scalar {
	dataset := make([][][]Scalar, p.Config.NumFiles)
	for i := 0; i < p.Config.NumFiles; i++ {
		fileChunks := make([][]Scalar, p.Config.ChunksPerFile)
		for j := 0; j < p.Config.ChunksPerFile; j++ {
			sectors := make([]Scalar, p.Config.SectorsPerChunk)
			for k := 0; k < p.Config.SectorsPerChunk; k++ {
				sectors[k] = p.Field.Random(p.rng, false)
			}
			fileChunks[j] = sectors
		}
		dataset[i] = fileChunks
	}
	return dataset
}

// chunkPolynomial 将一个分块中的扇区值视作多项式系数。
func (p *BatchPDPProtocol) chunkPolynomial(sectors []Scalar) Polynomial {
	return NewPolynomial(sectors, p.Field)
}

// merkleLeaf 将文件编号、分块编号和 KZG 标签绑定成 Merkle 叶子哈希。
func (p *BatchPDPProtocol) merkleLeaf(fileIndex, chunkIndex int, tag GroupElement) []byte {
	return stableHashBytes(p.Counter, "tag-leaf", fileIndex, chunkIndex, tag.Serialize())
}

// aggregatePolynomial 按挑战系数线性组合被抽查分块的多项式。
func (p *BatchPDPProtocol) aggregatePolynomial(storedFile StoredFile, challenge *Challenge) (Polynomial, error) {
	poly := NewPolynomial([]Scalar{p.Field.Zero()}, p.Field)
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

// aggregateTag 按挑战系数组合被抽查分块的 KZG 标签，得到聚合承诺 B_i。
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

// buildAuthPayload 为被抽查标签生成认证材料，可选择单路径证明或合并多重证明。
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

// fiatShamirAlpha 从公开 transcript 中派生每个文件对应的批聚合随机系数 alpha_i。
func (p *BatchPDPProtocol) fiatShamirAlpha(
	challenge *Challenge,
	roots [][]byte,
	fileProofs []FileProof,
	Cq GroupElement,
	Cqr GroupElement,
	fileIndex int,
) Scalar {
	bundle := transcriptBundle(fileProofs)
	return hashToField(p.Field, p.Counter, "alpha", challenge.ToPublicDict(), roots, bundle, Cq, Cqr, fileIndex)
}

// fiatShamirZ 从完整批证明 transcript 中派生批量 KZG 打开点 z。
func (p *BatchPDPProtocol) fiatShamirZ(
	challenge *Challenge,
	roots [][]byte,
	fileProofs []FileProof,
	Cq GroupElement,
	Cqr GroupElement,
	CQ GroupElement,
) Scalar {
	bundle := transcriptBundle(fileProofs)
	return hashToField(p.Field, p.Counter, "z", challenge.ToPublicDict(), roots, bundle, Cq, Cqr, CQ)
}

// Store 对输入数据生成每个分块的 KZG 标签和 Merkle 根，得到后续审计所需的存储状态。
func (p *BatchPDPProtocol) Store(dataset [][][]Scalar) (*StoredBatch, error) {
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
		sectorsCopy := make([][]Scalar, 0, len(fileChunks))

		for j, sectors := range fileChunks {
			if len(sectors) != p.Config.SectorsPerChunk {
				return nil, fmt.Errorf("file %d chunk %d: expected %d sectors, got %d", i, j, p.Config.SectorsPerChunk, len(sectors))
			}
			sectorCopy := make([]Scalar, len(sectors))
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

// Challenge 随机抽取分块索引、线性组合系数和每个文件的评估点。
func (p *BatchPDPProtocol) Challenge() *Challenge {
	perm := p.rng.Perm(p.Config.ChunksPerFile)
	indices := append([]int(nil), perm[:p.Config.ChallengedChunks]...)
	sort.Ints(indices)

	coefficients := make(map[int]Scalar, len(indices))
	for _, j := range indices {
		coefficients[j] = p.Field.Random(p.rng, true)
	}

	evaluationPoints := make([]Scalar, p.Config.NumFiles)
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

// ProofGen 根据存储状态和挑战生成批量 PDP 证明，包含认证路径、掩码值和批 KZG 打开证明。
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
		if !remainder.IsZero() {
			return nil, fmt.Errorf("quotient remainder non-zero for file %d", i)
		}

		fiPolys = append(fiPolys, fi)
		wiPolys = append(wiPolys, wi)
		fileProofs = append(fileProofs, FileProof{Auth: auth, B: bi, YTilde: yTildeI, R: Ri})
	}

	qPoly := NewPolynomial([]Scalar{p.Field.Zero()}, p.Field)
	Cqr := p.backend.Identity()
	for i, wi := range wiPolys {
		qPoly = qPoly.Add(wi)
		wiCommit := p.backend.CommitPolynomial(wi)
		Cqr = Cqr.Mul(wiCommit.Pow(challenge.EvaluationPoints[i]))
	}

	Cq := p.backend.CommitPolynomial(qPoly)

	alphas := make([]Scalar, p.Config.NumFiles)
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
	if !remainder.IsZero() {
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

// verifyAuth 验证单个文件的标签认证路径，并重新计算聚合标签是否与证明中的 B_i 一致。
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
	return bHat.Equal(fileProof.B)
}

// Verify 检查完整审计证明：先验证 Merkle 认证，再验证两个 KZG 配对关系。
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

	if !p.backend.PairingEqual(A.Mul(proof.Cqr), p.backend.G2Generator(), proof.Cq, p.backend.TauG2()) {
		return false
	}

	alphas := make([]Scalar, p.Config.NumFiles)
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

	return p.backend.PairingEqual(lhs, p.backend.G2Generator(), proof.PiBatch, p.backend.TauG2())
}

// CloneStoredBatch 深拷贝可变数据字段，方便测试篡改场景而不破坏原始存储状态。
func (p *BatchPDPProtocol) CloneStoredBatch(storedBatch *StoredBatch) *StoredBatch {
	clonedFiles := make([]StoredFile, len(storedBatch.Files))
	for i, storedFile := range storedBatch.Files {
		sectors := make([][]Scalar, len(storedFile.Sectors))
		for j, chunk := range storedFile.Sectors {
			sectors[j] = append([]Scalar(nil), chunk...)
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

// TamperChallengedSector 修改第一个被挑战分块的一个扇区，用于构造应被拒绝的反例。
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
	storedBatch.Files[0].Sectors[j][0] = p.Field.Add(storedBatch.Files[0].Sectors[j][0], p.Field.One())
	storedBatch.Files[0].Polynomials[j] = p.chunkPolynomial(storedBatch.Files[0].Sectors[j])
	return nil
}

type RoundResult struct {
	Proof    *AuditProof
	TimingMS map[string]float64
	Ops      map[string]map[string]int64
}

// MeasureRound 执行一次证明生成和验证，并分别记录耗时与操作计数差值。
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

// SizeReport 估算存储、挑战和证明的字节规模，并统计认证证明携带的哈希节点数量。
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

// ConfigDict 返回适合写入 JSON 的协议配置摘要。
func (p *BatchPDPProtocol) ConfigDict() map[string]any {
	return map[string]any{
		"num_files":         p.Config.NumFiles,
		"chunks_per_file":   p.Config.ChunksPerFile,
		"sectors_per_chunk": p.Config.SectorsPerChunk,
		"challenged_chunks": p.Config.ChallengedChunks,
		"prime_modulus":     p.Field.Modulus.String(),
		"field_bytes":       p.Config.FieldBytes,
		"group_bytes":       p.Config.GroupBytes,
		"hash_bytes":        p.Config.HashBytes,
		"rng_seed":          p.Config.RNGSeed,
	}
}

// validateStoredBatch 检查存储状态是否与当前协议配置匹配。
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

// validateChallenge 检查挑战索引、系数和评估点是否完整且无重复。
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
	YTilde string       `json:"y_tilde"`
	R      GroupElement `json:"R"`
}

// transcriptBundle 抽取 Fiat-Shamir 所需的证明公开字段，避免把认证路径等大对象纳入哈希。
func transcriptBundle(fileProofs []FileProof) []fileTranscript {
	bundle := make([]fileTranscript, len(fileProofs))
	for i, proof := range fileProofs {
		bundle[i] = fileTranscript{B: proof.B, YTilde: scalarHex(proof.YTilde), R: proof.R}
	}
	return bundle
}
