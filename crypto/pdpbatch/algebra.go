package pdpbatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"math/rand"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/kzg"
)

// Scalar 表示 BN254（BN256）标量域中的元素，是协议里所有有限域数值的基础类型。
type Scalar = fr.Element

// OperationCounter 记录实验用的哈希、群运算、配对和域运算次数，不用于精确密码学计费。
type OperationCounter struct {
	Hashes               int64
	Exponentiations      int64
	GroupMultiplications int64
	Pairings             int64
	FieldOps             int64
}

// Snapshot 返回当前计数器的不可变快照，便于后续计算两个阶段的操作差值。
func (c *OperationCounter) Snapshot() map[string]int64 {
	return map[string]int64{
		"hashes":                c.Hashes,
		"exponentiations":       c.Exponentiations,
		"group_multiplications": c.GroupMultiplications,
		"pairings":              c.Pairings,
		"field_ops":             c.FieldOps,
	}
}

// DiffCounters 计算两个计数器快照之间的差值，用于拆分证明生成和验证阶段的开销。
func DiffCounters(after, before map[string]int64) map[string]int64 {
	diff := make(map[string]int64, len(after))
	for key, value := range after {
		diff[key] = value - before[key]
	}
	return diff
}

type PrimeField struct {
	Modulus    *big.Int
	ByteLength int

	counter *OperationCounter
}

// NewPrimeField 创建 BN254（BN256）标量域封装，并校验传入模数是否与底层曲线实现一致。
func NewPrimeField(modulus string, counter *OperationCounter) (*PrimeField, error) {
	if counter == nil {
		counter = &OperationCounter{}
	}
	expected := fr.Modulus()
	if modulus != "" {
		parsed, ok := new(big.Int).SetString(modulus, 10)
		if !ok {
			return nil, errors.New("prime modulus must be a base-10 integer")
		}
		if parsed.Cmp(expected) != 0 {
			return nil, errors.New("pdpbatch uses the BN254 (BN256) scalar field modulus")
		}
	}
	return &PrimeField{
		Modulus:    new(big.Int).Set(expected),
		ByteLength: fr.Bytes,
		counter:    counter,
	}, nil
}

// Zero 返回标量域中的加法单位元。
func (f *PrimeField) Zero() Scalar {
	var out Scalar
	out.SetZero()
	return out
}

// One 返回标量域中的乘法单位元。
func (f *PrimeField) One() Scalar {
	return fr.One()
}

// FromUint64 将普通整数转换为标量域元素。
func (f *PrimeField) FromUint64(value uint64) Scalar {
	var out Scalar
	out.SetUint64(value)
	return out
}

// Normalize 保持标量元素处于规范域表示；gnark-crypto 的 Element 本身已自动规约。
func (f *PrimeField) Normalize(value Scalar) Scalar {
	return value
}

// Add 执行标量域加法，并更新域运算计数。
func (f *PrimeField) Add(left, right Scalar) Scalar {
	f.counter.FieldOps++
	var out Scalar
	out.Add(&left, &right)
	return out
}

// Sub 执行标量域减法，并更新域运算计数。
func (f *PrimeField) Sub(left, right Scalar) Scalar {
	f.counter.FieldOps++
	var out Scalar
	out.Sub(&left, &right)
	return out
}

// Neg 返回标量域中的相反数。
func (f *PrimeField) Neg(value Scalar) Scalar {
	var out Scalar
	out.Neg(&value)
	return out
}

// Mul 执行标量域乘法，并更新域运算计数。
func (f *PrimeField) Mul(left, right Scalar) Scalar {
	f.counter.FieldOps++
	var out Scalar
	out.Mul(&left, &right)
	return out
}

// Inv 计算非零标量的乘法逆元，零元素会返回错误。
func (f *PrimeField) Inv(value Scalar) (Scalar, error) {
	f.counter.FieldOps++
	if value.IsZero() {
		return Scalar{}, errors.New("zero has no multiplicative inverse")
	}
	var out Scalar
	out.Inverse(&value)
	return out, nil
}

// Div 通过求逆实现标量域除法，并把零分母错误向上传递。
func (f *PrimeField) Div(numerator, denominator Scalar) (Scalar, error) {
	inverse, err := f.Inv(denominator)
	if err != nil {
		return Scalar{}, err
	}
	return f.Mul(numerator, inverse), nil
}

// Random 使用传入随机源采样标量；nonzero 为真时会拒绝零元素。
func (f *PrimeField) Random(rng *rand.Rand, nonzero bool) Scalar {
	for {
		var buf [fr.Bytes]byte
		for i := range buf {
			buf[i] = byte(rng.Intn(256))
		}
		value := new(big.Int).SetBytes(buf[:])
		value.Mod(value, f.Modulus)

		var out Scalar
		out.SetBigInt(value)
		if !nonzero || !out.IsZero() {
			return out
		}
	}
}

type Polynomial struct {
	coeffs []Scalar
	field  *PrimeField
}

// NewPolynomial 根据低次到高次排列的系数构造多项式，并移除多余的最高位零系数。
func NewPolynomial(coeffs []Scalar, field *PrimeField) Polynomial {
	if len(coeffs) == 0 {
		coeffs = []Scalar{field.Zero()}
	}
	out := make([]Scalar, len(coeffs))
	for i, coeff := range coeffs {
		out[i] = field.Normalize(coeff)
	}
	p := Polynomial{coeffs: out, field: field}
	p.trim()
	return p
}

// trim 删除最高次的零系数，使多项式保持规范表示。
func (p *Polynomial) trim() {
	for len(p.coeffs) > 1 && p.coeffs[len(p.coeffs)-1].IsZero() {
		p.coeffs = p.coeffs[:len(p.coeffs)-1]
	}
}

// Degree 返回多项式次数；零多项式在本实现中表示为一次系数切片并返回 0。
func (p Polynomial) Degree() int {
	return len(p.coeffs) - 1
}

// Coefficients 返回系数副本，防止调用方修改多项式内部状态。
func (p Polynomial) Coefficients() []Scalar {
	out := make([]Scalar, len(p.coeffs))
	copy(out, p.coeffs)
	return out
}

// Evaluate 使用 Horner 法在指定点上计算多项式值。
func (p Polynomial) Evaluate(point Scalar) Scalar {
	result := p.field.Zero()
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		result = p.field.Mul(result, point)
		result = p.field.Add(result, p.coeffs[i])
		if i == 0 {
			break
		}
	}
	return result
}

// Add 返回两个多项式的逐项和。
func (p Polynomial) Add(other Polynomial) Polynomial {
	size := len(p.coeffs)
	if len(other.coeffs) > size {
		size = len(other.coeffs)
	}
	out := make([]Scalar, size)
	for i := 0; i < size; i++ {
		left := p.field.Zero()
		right := p.field.Zero()
		if i < len(p.coeffs) {
			left = p.coeffs[i]
		}
		if i < len(other.coeffs) {
			right = other.coeffs[i]
		}
		out[i] = p.field.Add(left, right)
	}
	return NewPolynomial(out, p.field)
}

// Scale 返回多项式乘以标量后的结果。
func (p Polynomial) Scale(scalar Scalar) Polynomial {
	out := make([]Scalar, len(p.coeffs))
	for i, coeff := range p.coeffs {
		out[i] = p.field.Mul(coeff, scalar)
	}
	return NewPolynomial(out, p.field)
}

// SubtractConstant 从常数项中减去给定标量，常用于构造 f(x)-f(r)。
func (p Polynomial) SubtractConstant(constant Scalar) Polynomial {
	out := p.Coefficients()
	out[0] = p.field.Sub(out[0], constant)
	return NewPolynomial(out, p.field)
}

// DivideByLinear 用综合除法计算 p(x)/(x-root)，同时返回余数。
func (p Polynomial) DivideByLinear(root Scalar) (Polynomial, Scalar) {
	if len(p.coeffs) == 1 {
		return NewPolynomial([]Scalar{p.field.Zero()}, p.field), p.coeffs[0]
	}

	quotient := make([]Scalar, len(p.coeffs)-1)
	carry := p.coeffs[len(p.coeffs)-1]
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		quotient[i] = carry
		carry = p.field.Add(p.coeffs[i], p.field.Mul(root, carry))
		if i == 0 {
			break
		}
	}
	return NewPolynomial(quotient, p.field), carry
}

type GroupElement struct {
	Point bn254.G1Affine

	backend *CurveKZGBackend
}

// Mul 执行 G1 群元素相加；在指数记法下等价于承诺相乘。
func (g GroupElement) Mul(other GroupElement) GroupElement {
	if g.backend != other.backend {
		panic("group elements must share the same backend")
	}
	g.backend.counter.GroupMultiplications++

	var out bn254.G1Affine
	out.Add(&g.Point, &other.Point)
	return GroupElement{Point: out, backend: g.backend}
}

// Pow 将 G1 群元素按标量做倍乘；在承诺语义下表示承诺的标量幂。
func (g GroupElement) Pow(scalar Scalar) GroupElement {
	g.backend.counter.Exponentiations++

	var out bn254.G1Affine
	out.ScalarMultiplication(&g.Point, scalarBigInt(scalar))
	return GroupElement{Point: out, backend: g.backend}
}

// Equal 判断两个 G1 群元素是否完全相同。
func (g GroupElement) Equal(other GroupElement) bool {
	return g.Point.Equal(&other.Point)
}

// Serialize 返回 G1 点的压缩字节表示副本，供哈希和 JSON 序列化使用。
func (g GroupElement) Serialize() []byte {
	encoded := g.Point.Bytes()
	out := make([]byte, len(encoded))
	copy(out, encoded[:])
	return out
}

// MarshalJSON 将群元素编码为十六进制压缩 G1 点，保证 transcript 可稳定序列化。
func (g GroupElement) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"g1_compressed": hex.EncodeToString(g.Serialize())})
}

type CurveKZGBackend struct {
	field   *PrimeField
	srs     *kzg.SRS
	counter *OperationCounter
}

// NewCurveKZGBackend 生成实验用 KZG SRS，并返回基于 BN254（BN256）曲线群的承诺后端。
func NewCurveKZGBackend(field *PrimeField, maxPolynomialSize int, rng *rand.Rand, counter *OperationCounter) (*CurveKZGBackend, error) {
	if maxPolynomialSize <= 0 {
		return nil, errors.New("max polynomial size must be positive")
	}
	if counter == nil {
		counter = field.counter
	}

	alpha := field.Random(rng, true)
	srs, err := kzg.NewSRS(uint64(maxPolynomialSize), scalarBigInt(alpha))
	if err != nil {
		return nil, err
	}

	return &CurveKZGBackend{
		field:   field,
		srs:     srs,
		counter: counter,
	}, nil
}

// Generator 返回 G1 生成元封装，作为协议中 g 的基础承诺元素。
func (b *CurveKZGBackend) Generator() GroupElement {
	return GroupElement{Point: b.srs.Vk.G1, backend: b}
}

// Identity 返回 G1 群的单位元，用于累加承诺时的初始值。
func (b *CurveKZGBackend) Identity() GroupElement {
	var point bn254.G1Affine
	point.SetInfinity()
	return GroupElement{Point: point, backend: b}
}

// CommitScalar 将一个标量承诺为 scalar*g，常用于隐藏随机掩码。
func (b *CurveKZGBackend) CommitScalar(scalar Scalar) GroupElement {
	b.counter.Exponentiations++

	var point bn254.G1Affine
	point.ScalarMultiplication(&b.srs.Vk.G1, scalarBigInt(scalar))
	return GroupElement{Point: point, backend: b}
}

// CommitPolynomial 使用 KZG SRS 对多项式生成 G1 承诺。
func (b *CurveKZGBackend) CommitPolynomial(polynomial Polynomial) GroupElement {
	b.counter.Exponentiations++

	digest, err := kzg.Commit(polynomial.Coefficients(), b.srs.Pk)
	if err != nil {
		panic(err)
	}
	return GroupElement{Point: digest, backend: b}
}

// G2Generator 返回配对检查中使用的 G2 生成元。
func (b *CurveKZGBackend) G2Generator() bn254.G2Affine {
	return b.srs.Vk.G2[0]
}

// TauG2 返回 SRS 中的 tau*G2，用于验证 KZG 打开关系。
func (b *CurveKZGBackend) TauG2() bn254.G2Affine {
	return b.srs.Vk.G2[1]
}

// PairingEqual 检查 e(left,leftG2) 是否等于 e(right,rightG2)，并记录两次配对开销。
func (b *CurveKZGBackend) PairingEqual(left GroupElement, leftG2 bn254.G2Affine, right GroupElement, rightG2 bn254.G2Affine) bool {
	b.counter.Pairings += 2

	negRight := right.Point
	negRight.Neg(&negRight)
	ok, err := bn254.PairingCheck(
		[]bn254.G1Affine{left.Point, negRight},
		[]bn254.G2Affine{leftG2, rightG2},
	)
	return err == nil && ok
}

// nextPowerOfTwo 返回不小于 value 的最小 2 的幂，用于 Merkle 树补齐叶子数量。
func nextPowerOfTwo(value int) int {
	result := 1
	for result < value {
		result <<= 1
	}
	return result
}

// stableHashBytes 先将输入片段编码为 JSON，再计算 SHA-256，确保 transcript 哈希稳定可复现。
func stableHashBytes(counter *OperationCounter, parts ...any) []byte {
	payload, err := json.Marshal(parts)
	if err != nil {
		panic(err)
	}
	if counter != nil {
		counter.Hashes++
	}
	digest := sha256.Sum256(payload)
	out := make([]byte, len(digest))
	copy(out, digest[:])
	return out
}

// hashToField 带标签哈希 transcript，并把摘要规约到标量域中。
func hashToField(field *PrimeField, counter *OperationCounter, label string, parts ...any) Scalar {
	all := make([]any, 0, len(parts)+1)
	all = append(all, label)
	all = append(all, parts...)
	digest := stableHashBytes(counter, all...)

	value := new(big.Int).SetBytes(digest)
	value.Mod(value, field.Modulus)
	var out Scalar
	out.SetBigInt(value)
	return out
}

// scalarBigInt 将标量转换为 big.Int，供曲线标量乘法和 SRS 构造使用。
func scalarBigInt(value Scalar) *big.Int {
	var out big.Int
	value.BigInt(&out)
	return &out
}

// scalarEqual 比较两个标量的规范值。
func scalarEqual(left, right Scalar) bool {
	var leftInt big.Int
	var rightInt big.Int
	left.BigInt(&leftInt)
	right.BigInt(&rightInt)
	return leftInt.Cmp(&rightInt) == 0
}

// scalarHex 返回标量的定长十六进制编码，便于稳定输出和哈希绑定。
func scalarHex(value Scalar) string {
	encoded := value.Bytes()
	return hex.EncodeToString(encoded[:])
}

// scalarDecimal 返回标量的十进制表示，主要用于报告和调试输出。
func scalarDecimal(value Scalar) string {
	return value.String()
}
