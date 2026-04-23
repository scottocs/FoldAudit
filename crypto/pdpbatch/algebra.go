package pdpbatch

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math/big"
	"math/bits"
	"math/rand"
)

// OperationCounter mirrors the lightweight instrumentation used by the Python
// prototype. The counters are intended for experiments, not cryptographic
// metering.
type OperationCounter struct {
	Hashes               int64
	Exponentiations      int64
	GroupMultiplications int64
	Pairings             int64
	FieldOps             int64
}

func (c *OperationCounter) Snapshot() map[string]int64 {
	return map[string]int64{
		"hashes":                c.Hashes,
		"exponentiations":       c.Exponentiations,
		"group_multiplications": c.GroupMultiplications,
		"pairings":              c.Pairings,
		"field_ops":             c.FieldOps,
	}
}

func DiffCounters(after, before map[string]int64) map[string]int64 {
	diff := make(map[string]int64, len(after))
	for key, value := range after {
		diff[key] = value - before[key]
	}
	return diff
}

type PrimeField struct {
	Modulus    uint64
	ByteLength int

	counter    *OperationCounter
	modulusBig *big.Int
}

func NewPrimeField(modulus uint64, counter *OperationCounter) (*PrimeField, error) {
	const maxInt64 = uint64(1<<63 - 1)
	if modulus <= 2 {
		return nil, errors.New("modulus must be an odd prime")
	}
	if modulus > maxInt64 {
		return nil, errors.New("modulus must fit in int64 for deterministic sampling")
	}
	if counter == nil {
		counter = &OperationCounter{}
	}
	return &PrimeField{
		Modulus:    modulus,
		ByteLength: (bits.Len64(modulus) + 7) / 8,
		counter:    counter,
		modulusBig: new(big.Int).SetUint64(modulus),
	}, nil
}

func (f *PrimeField) Normalize(value uint64) uint64 {
	return value % f.Modulus
}

func (f *PrimeField) Add(left, right uint64) uint64 {
	f.counter.FieldOps++
	return f.addNoCount(left, right)
}

func (f *PrimeField) addNoCount(left, right uint64) uint64 {
	sum := left + right
	if sum >= f.Modulus {
		sum -= f.Modulus
	}
	return sum
}

func (f *PrimeField) Sub(left, right uint64) uint64 {
	f.counter.FieldOps++
	if left >= right {
		return left - right
	}
	return f.Modulus - (right - left)
}

func (f *PrimeField) Neg(value uint64) uint64 {
	if value == 0 {
		return 0
	}
	return f.Modulus - value
}

func (f *PrimeField) Mul(left, right uint64) uint64 {
	f.counter.FieldOps++
	return f.mulNoCount(left, right)
}

func (f *PrimeField) mulNoCount(left, right uint64) uint64 {
	var product big.Int
	product.Mul(new(big.Int).SetUint64(left), new(big.Int).SetUint64(right))
	product.Mod(&product, f.modulusBig)
	return product.Uint64()
}

func (f *PrimeField) Inv(value uint64) (uint64, error) {
	f.counter.FieldOps++
	if value%f.Modulus == 0 {
		return 0, errors.New("zero has no multiplicative inverse")
	}
	inverse := new(big.Int).ModInverse(new(big.Int).SetUint64(value), f.modulusBig)
	if inverse == nil {
		return 0, errors.New("value has no multiplicative inverse")
	}
	return inverse.Uint64(), nil
}

func (f *PrimeField) Div(numerator, denominator uint64) (uint64, error) {
	inverse, err := f.Inv(denominator)
	if err != nil {
		return 0, err
	}
	return f.Mul(numerator, inverse), nil
}

func (f *PrimeField) Random(rng *rand.Rand, nonzero bool) uint64 {
	if nonzero {
		return uint64(rng.Int63n(int64(f.Modulus-1))) + 1
	}
	return uint64(rng.Int63n(int64(f.Modulus)))
}

type Polynomial struct {
	coeffs []uint64
	field  *PrimeField
}

func NewPolynomial(coeffs []uint64, field *PrimeField) Polynomial {
	if len(coeffs) == 0 {
		coeffs = []uint64{0}
	}
	out := make([]uint64, len(coeffs))
	for i, coeff := range coeffs {
		out[i] = field.Normalize(coeff)
	}
	p := Polynomial{coeffs: out, field: field}
	p.trim()
	return p
}

func (p *Polynomial) trim() {
	for len(p.coeffs) > 1 && p.coeffs[len(p.coeffs)-1] == 0 {
		p.coeffs = p.coeffs[:len(p.coeffs)-1]
	}
}

func (p Polynomial) Degree() int {
	return len(p.coeffs) - 1
}

func (p Polynomial) Coefficients() []uint64 {
	out := make([]uint64, len(p.coeffs))
	copy(out, p.coeffs)
	return out
}

func (p Polynomial) Evaluate(point uint64) uint64 {
	var result uint64
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		result = p.field.Mul(result, point)
		result = p.field.Add(result, p.coeffs[i])
		if i == 0 {
			break
		}
	}
	return result
}

func (p Polynomial) Add(other Polynomial) Polynomial {
	size := len(p.coeffs)
	if len(other.coeffs) > size {
		size = len(other.coeffs)
	}
	out := make([]uint64, size)
	for i := 0; i < size; i++ {
		var left, right uint64
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

func (p Polynomial) Scale(scalar uint64) Polynomial {
	out := make([]uint64, len(p.coeffs))
	for i, coeff := range p.coeffs {
		out[i] = p.field.Mul(coeff, scalar)
	}
	return NewPolynomial(out, p.field)
}

func (p Polynomial) SubtractConstant(constant uint64) Polynomial {
	out := p.Coefficients()
	out[0] = p.field.Sub(out[0], constant)
	return NewPolynomial(out, p.field)
}

func (p Polynomial) DivideByLinear(root uint64) (Polynomial, uint64) {
	if len(p.coeffs) == 1 {
		return NewPolynomial([]uint64{0}, p.field), p.coeffs[0]
	}

	quotient := make([]uint64, len(p.coeffs)-1)
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
	Exponent uint64

	backend *AlgebraicKZGBackend
}

func (g GroupElement) Mul(other GroupElement) GroupElement {
	if g.backend != other.backend {
		panic("group elements must share the same backend")
	}
	g.backend.counter.GroupMultiplications++
	return GroupElement{
		Exponent: g.backend.field.addNoCount(g.Exponent, other.Exponent),
		backend:  g.backend,
	}
}

func (g GroupElement) Pow(scalar uint64) GroupElement {
	g.backend.counter.Exponentiations++
	return GroupElement{
		Exponent: g.backend.field.mulNoCount(g.Exponent, scalar),
		backend:  g.backend,
	}
}

func (g GroupElement) Serialize() []byte {
	out := make([]byte, g.backend.field.ByteLength)
	value := g.Exponent
	for i := len(out) - 1; i >= 0; i-- {
		out[i] = byte(value)
		value >>= 8
	}
	return out
}

func (g GroupElement) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]uint64{"group_exp": g.Exponent})
}

type AlgebraicKZGBackend struct {
	field   *PrimeField
	Tau     uint64
	counter *OperationCounter
}

func NewAlgebraicKZGBackend(field *PrimeField, tau uint64, counter *OperationCounter) *AlgebraicKZGBackend {
	if counter == nil {
		counter = field.counter
	}
	return &AlgebraicKZGBackend{
		field:   field,
		Tau:     field.Normalize(tau),
		counter: counter,
	}
}

func (b *AlgebraicKZGBackend) Generator() GroupElement {
	return GroupElement{Exponent: 1, backend: b}
}

func (b *AlgebraicKZGBackend) Identity() GroupElement {
	return GroupElement{Exponent: 0, backend: b}
}

func (b *AlgebraicKZGBackend) CommitScalar(scalar uint64) GroupElement {
	b.counter.Exponentiations++
	return GroupElement{Exponent: b.field.Normalize(scalar), backend: b}
}

func (b *AlgebraicKZGBackend) CommitPolynomial(polynomial Polynomial) GroupElement {
	b.counter.Exponentiations++
	return GroupElement{Exponent: polynomial.Evaluate(b.Tau), backend: b}
}

func (b *AlgebraicKZGBackend) Pairing(left GroupElement, rightExponent uint64) uint64 {
	b.counter.Pairings++
	return b.field.Mul(left.Exponent, rightExponent)
}

func nextPowerOfTwo(value int) int {
	result := 1
	for result < value {
		result <<= 1
	}
	return result
}

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

func hashToField(field *PrimeField, counter *OperationCounter, label string, parts ...any) uint64 {
	all := make([]any, 0, len(parts)+1)
	all = append(all, label)
	all = append(all, parts...)
	digest := stableHashBytes(counter, all...)
	value := new(big.Int).SetBytes(digest)
	value.Mod(value, field.modulusBig)
	return value.Uint64()
}
