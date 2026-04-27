package pdpbatch

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"
)

const DefaultPrimeModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

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
		GroupBytes:       32,
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
	Auth    AuthPayload
	YTilde  Scalar
	R       GroupElement
	Cw      GroupElement
	VZTilde Scalar
	S       GroupElement
}

type AuditProof struct {
	AuthMode   AuthMode
	FileProofs []FileProof
	B          GroupElement
	VTildeW    Scalar
	RW         GroupElement
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

// merkleLeaf 将分块编号和 KZG 标签绑定成 Merkle 叶子哈希。
func (p *BatchPDPProtocol) merkleLeaf(chunkIndex int, tag GroupElement) []byte {
	return stableHashBytes(p.Counter, "tag-leaf", chunkIndex, tag.Serialize())
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

// fiatShamirRho 从所有 per-file quotient commitments 固定后的 transcript 中派生折叠标量 rho。
func (p *BatchPDPProtocol) fiatShamirRho(challenge *Challenge, roots [][]byte, b GroupElement, fileProofs []FileProof) Scalar {
	bundle := transcriptBundle(fileProofs)
	return hashToField(p.Field, p.Counter, "foldaudit-rho", challenge.ToPublicDict(), roots, b, bundle, "1")
}

// fiatShamirZ 从同一 transcript 中派生批量打开点 z，并避免与任一 r_i 相等。
func (p *BatchPDPProtocol) fiatShamirZ(challenge *Challenge, roots [][]byte, b GroupElement, fileProofs []FileProof) Scalar {
	bundle := transcriptBundle(fileProofs)
	for attempt := 0; ; attempt++ {
		z := hashToField(p.Field, p.Counter, "foldaudit-z", challenge.ToPublicDict(), roots, b, bundle, "2", attempt)
		collides := false
		for _, ri := range challenge.EvaluationPoints {
			if scalarEqual(z, ri) {
				collides = true
				break
			}
		}
		if !collides {
			return z
		}
	}
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
			leaf := p.merkleLeaf(j, tag)

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

// ProofGen 根据新版 FoldAudit 流程生成链下批量 PDP 证明。
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
	b := p.backend.Identity()

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
		Cwi := p.backend.CommitPolynomial(wi)

		b = b.Mul(bi)
		fiPolys = append(fiPolys, fi)
		wiPolys = append(wiPolys, wi)
		fileProofs = append(fileProofs, FileProof{
			Auth:   auth,
			YTilde: yTildeI,
			R:      Ri,
			Cw:     Cwi,
		})
	}

	rho := p.fiatShamirRho(challenge, storedBatch.Roots, b, fileProofs)
	WPoly := NewPolynomial([]Scalar{p.Field.Zero()}, p.Field)
	rhoPower := p.Field.One()
	for _, wi := range wiPolys {
		WPoly = WPoly.Add(wi.Scale(rhoPower))
		rhoPower = p.Field.Mul(rhoPower, rho)
	}

	z := p.fiatShamirZ(challenge, storedBatch.Roots, b, fileProofs)
	VW := WPoly.Evaluate(z)
	for i, fi := range fiPolys {
		viZ := fi.Evaluate(z)
		nuI := p.Field.Random(p.rng, false)
		fileProofs[i].VZTilde = p.Field.Add(viZ, nuI)
		fileProofs[i].S = p.backend.CommitScalar(nuI)
	}
	eta := p.Field.Random(p.rng, false)
	VTildeW := p.Field.Add(VW, eta)
	RW := p.backend.CommitScalar(eta)

	piPoly, remainder := WPoly.SubtractConstant(VW).DivideByLinear(z)
	if !remainder.IsZero() {
		return nil, errors.New("opening quotient remainder non-zero")
	}
	piBatch := p.backend.CommitPolynomial(piPoly)

	return &AuditProof{
		AuthMode:   authMode,
		FileProofs: fileProofs,
		B:          b,
		VTildeW:    VTildeW,
		RW:         RW,
		PiBatch:    piBatch,
	}, nil
}

// verifyAuth 验证单个文件的标签认证路径。
func (p *BatchPDPProtocol) verifyAuth(root []byte, fileProof FileProof, challenge *Challenge, authMode AuthMode) bool {
	leafHashes := make(map[int][]byte, len(challenge.Indices))
	for _, j := range challenge.Indices {
		tag, ok := fileProof.Auth.Tags[j]
		if !ok {
			return false
		}
		leafHashes[j] = p.merkleLeaf(j, tag)
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
	return true
}

// aggregateProofTag 根据证明携带的被挑战标签重算单文件聚合标签。
func (p *BatchPDPProtocol) aggregateProofTag(fileProof FileProof, challenge *Challenge) (GroupElement, bool) {
	result := p.backend.Identity()
	for _, j := range challenge.Indices {
		tag, ok := fileProof.Auth.Tags[j]
		if !ok {
			return GroupElement{}, false
		}
		coefficient, ok := challenge.Coefficients[j]
		if !ok {
			return GroupElement{}, false
		}
		result = result.Mul(tag.Pow(coefficient))
	}
	return result, true
}

// Verify 检查完整审计证明：认证标签、重算折叠承诺、验证批量打开与隐藏评估一致性。
func (p *BatchPDPProtocol) Verify(storedBatch *StoredBatch, challenge *Challenge, proof *AuditProof) bool {
	if p.validateStoredBatch(storedBatch) != nil || p.validateChallenge(challenge) != nil || proof == nil {
		return false
	}
	if len(proof.FileProofs) != p.Config.NumFiles {
		return false
	}

	perFileTags := make([]GroupElement, p.Config.NumFiles)
	bHat := p.backend.Identity()
	for i := 0; i < p.Config.NumFiles; i++ {
		if !p.verifyAuth(storedBatch.Roots[i], proof.FileProofs[i], challenge, proof.AuthMode) {
			return false
		}
		bi, ok := p.aggregateProofTag(proof.FileProofs[i], challenge)
		if !ok {
			return false
		}
		perFileTags[i] = bi
		bHat = bHat.Mul(bi)
	}
	if !bHat.Equal(proof.B) {
		return false
	}

	rho := p.fiatShamirRho(challenge, storedBatch.Roots, proof.B, proof.FileProofs)
	CW := p.backend.Identity()
	rhoPower := p.Field.One()
	for i := 0; i < p.Config.NumFiles; i++ {
		CW = CW.Mul(proof.FileProofs[i].Cw.Pow(rhoPower))
		rhoPower = p.Field.Mul(rhoPower, rho)
	}

	if !p.verifyFoldedQuotientBinding(perFileTags, challenge, proof, rho, CW) {
		return false
	}

	z := p.fiatShamirZ(challenge, storedBatch.Roots, proof.B, proof.FileProofs)
	openingLHS := CW.
		Mul(p.g.Pow(p.Field.Neg(proof.VTildeW))).
		Mul(proof.RW).
		Mul(proof.PiBatch.Pow(z))
	if !p.backend.PairingEqual(openingLHS, p.backend.G2Generator(), proof.PiBatch, p.backend.TauG2()) {
		return false
	}

	evalLHS, evalRHS, ok := p.maskedEvaluationSides(challenge, proof, rho, z)
	return ok && evalLHS.Equal(evalRHS)
}

// verifyFoldedQuotientBinding 将 Merkle 认证过的聚合标签与折叠 quotient commitments 绑定。
func (p *BatchPDPProtocol) verifyFoldedQuotientBinding(
	perFileTags []GroupElement,
	challenge *Challenge,
	proof *AuditProof,
	rho Scalar,
	CW GroupElement,
) bool {
	if len(perFileTags) != len(proof.FileProofs) {
		return false
	}

	left := p.backend.Identity()
	rhoPower := p.Field.One()
	for i, fp := range proof.FileProofs {
		term := perFileTags[i].
			Mul(fp.R).
			Mul(p.g.Pow(p.Field.Neg(fp.YTilde))).
			Mul(fp.Cw.Pow(challenge.EvaluationPoints[i]))
		left = left.Mul(term.Pow(rhoPower))
		rhoPower = p.Field.Mul(rhoPower, rho)
	}
	return p.backend.PairingEqual(left, p.backend.G2Generator(), CW, p.backend.TauG2())
}

// maskedEvaluationSides 构造 PDF Algorithm 5 Step 4 的隐藏评估一致性等式两侧。
func (p *BatchPDPProtocol) maskedEvaluationSides(
	challenge *Challenge,
	proof *AuditProof,
	rho Scalar,
	z Scalar,
) (GroupElement, GroupElement, bool) {
	negOne := p.Field.Neg(p.Field.One())
	sum := p.Field.Zero()
	rhs := p.backend.Identity()
	rhoPower := p.Field.One()

	for i, fp := range proof.FileProofs {
		denominator := p.Field.Sub(z, challenge.EvaluationPoints[i])
		if denominator.IsZero() {
			return GroupElement{}, GroupElement{}, false
		}
		inverseDenominator, err := p.Field.Inv(denominator)
		if err != nil {
			return GroupElement{}, GroupElement{}, false
		}
		scale := p.Field.Mul(rhoPower, inverseDenominator)
		diff := p.Field.Sub(fp.VZTilde, fp.YTilde)
		sum = p.Field.Add(sum, p.Field.Mul(scale, diff))

		maskTerm := fp.R.Mul(fp.S.Pow(negOne))
		rhs = rhs.Mul(maskTerm.Pow(scale))
		rhoPower = p.Field.Mul(rhoPower, rho)
	}

	lhs := p.g.Pow(proof.VTildeW).
		Mul(proof.RW.Pow(negOne)).
		Mul(p.g.Pow(p.Field.Neg(sum)))
	return lhs, rhs, true
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
		p.Config.NumFiles*3*p.Config.GroupBytes +
		p.Config.NumFiles*2*p.Config.FieldBytes +
		authHashNodes*p.Config.HashBytes +
		3*p.Config.GroupBytes +
		p.Config.FieldBytes

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
	YTilde string       `json:"y_tilde"`
	R      GroupElement `json:"R"`
	Cw     GroupElement `json:"Cw"`
}

// transcriptBundle 抽取 Fiat-Shamir 所需的证明公开字段，避免把认证路径等大对象纳入哈希。
func transcriptBundle(fileProofs []FileProof) []fileTranscript {
	bundle := make([]fileTranscript, len(fileProofs))
	for i, proof := range fileProofs {
		bundle[i] = fileTranscript{YTilde: scalarHex(proof.YTilde), R: proof.R, Cw: proof.Cw}
	}
	return bundle
}
