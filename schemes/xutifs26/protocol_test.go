package xutifs26

import (
	"bytes"
	"math/big"
	"testing"

	"foldaudit/schemes/benchcore"
)

func TestProveDoesNotUseTrapdoor(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := NewProtocol(m, n, s)
	stored, err := p.Store(testDataset(m, n, s, "xu/no-trapdoor"))
	if err != nil {
		t.Fatal(err)
	}
	chal := p.ChallengeFromSeed([]byte("xu-no-trapdoor-proofgen"), c)

	p.alpha = nil

	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest proof generated without trapdoor was rejected")
	}
}

func TestChallengeUsesFreshRandomSeed(t *testing.T) {
	p := NewProtocol(3, 32, 4)
	chalA := p.Challenge(8)
	chalB := p.Challenge(8)
	if bytes.Equal(chalA.Seed, chalB.Seed) {
		t.Fatal("Challenge reused random seed")
	}
	assertUniqueInRange(t, chalA.Indices, 8, p.N)
	assertUniqueInRange(t, chalB.Indices, 8, p.N)
}

func testDataset(m, n, s int, label string) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := 0; i < m; i++ {
		out[i] = make([][]*big.Int, n)
		for j := 0; j < n; j++ {
			out[i][j] = make([]*big.Int, s)
			for k := 0; k < s; k++ {
				out[i][j][k] = benchcore.Scalar(label, i*n*s+j*s+k)
			}
		}
	}
	return out
}

func assertUniqueInRange(t *testing.T, indices []int, want, n int) {
	t.Helper()
	if len(indices) != want {
		t.Fatalf("expected %d indices, got %d", want, len(indices))
	}
	seen := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		if index < 0 || index >= n {
			t.Fatalf("challenge index %d out of range", index)
		}
		if _, ok := seen[index]; ok {
			t.Fatalf("duplicate challenge index %d", index)
		}
		seen[index] = struct{}{}
	}
}
