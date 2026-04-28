package foldaudit

import "math/big"

// Polynomial stores coefficients in little-endian order: c[0] + c[1]X + ...
type Polynomial struct {
	coeffs []*big.Int
}

func NewPolynomial(coeffs []*big.Int) Polynomial {
	if len(coeffs) == 0 {
		coeffs = []*big.Int{scalarZero()}
	}
	out := make([]*big.Int, len(coeffs))
	for i, coeff := range coeffs {
		out[i] = cloneScalar(coeff)
	}
	p := Polynomial{coeffs: out}
	p.trim()
	return p
}

func (p *Polynomial) trim() {
	for len(p.coeffs) > 1 && p.coeffs[len(p.coeffs)-1].Sign() == 0 {
		p.coeffs = p.coeffs[:len(p.coeffs)-1]
	}
}

func (p Polynomial) Degree() int {
	return len(p.coeffs) - 1
}

func (p Polynomial) Coefficients() []*big.Int {
	out := make([]*big.Int, len(p.coeffs))
	for i, coeff := range p.coeffs {
		out[i] = cloneScalar(coeff)
	}
	return out
}

func (p Polynomial) Evaluate(point *big.Int) *big.Int {
	point = normalizeScalar(point)
	result := scalarZero()
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		result = scalarAdd(scalarMul(result, point), p.coeffs[i])
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
	out := make([]*big.Int, size)
	for i := 0; i < size; i++ {
		left := scalarZero()
		right := scalarZero()
		if i < len(p.coeffs) {
			left = p.coeffs[i]
		}
		if i < len(other.coeffs) {
			right = other.coeffs[i]
		}
		out[i] = scalarAdd(left, right)
	}
	return NewPolynomial(out)
}

func (p Polynomial) Scale(k *big.Int) Polynomial {
	out := make([]*big.Int, len(p.coeffs))
	for i, coeff := range p.coeffs {
		out[i] = scalarMul(coeff, k)
	}
	return NewPolynomial(out)
}

func (p Polynomial) SubtractConstant(c *big.Int) Polynomial {
	out := p.Coefficients()
	out[0] = scalarSub(out[0], c)
	return NewPolynomial(out)
}

// DivideByLinear divides p(X) by X-root and returns the quotient and remainder.
func (p Polynomial) DivideByLinear(root *big.Int) (Polynomial, *big.Int) {
	root = normalizeScalar(root)
	if len(p.coeffs) == 1 {
		return NewPolynomial([]*big.Int{scalarZero()}), cloneScalar(p.coeffs[0])
	}

	quotient := make([]*big.Int, len(p.coeffs)-1)
	carry := cloneScalar(p.coeffs[len(p.coeffs)-1])
	for i := len(p.coeffs) - 2; i >= 0; i-- {
		quotient[i] = cloneScalar(carry)
		carry = scalarAdd(p.coeffs[i], scalarMul(root, carry))
		if i == 0 {
			break
		}
	}
	return NewPolynomial(quotient), carry
}
