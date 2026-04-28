package zhangtpds23

import (
	"bytes"
	"math/big"
	"testing"

	"foldaudit/schemes/benchcore"
)

func TestProveDoesNotUseTrapdoorScalars(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := NewProtocol(m, n, s)
	stored, err := p.Store(testDataset(m, n, s, "zhang/no-trapdoor"))
	if err != nil {
		t.Fatal(err)
	}
	chal := p.ChallengeFromSeed([]byte("zhang-no-trapdoor-proofgen"), c)

	p.alpha = nil
	p.x = nil

	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest proof generated without trapdoor scalars was rejected")
	}
}

func TestChallengeUsesFreshRandomSeed(t *testing.T) {
	m, n, s, c := 3, 32, 4, 8
	p := NewProtocol(m, n, s)
	chalA := p.Challenge(c)
	chalB := p.Challenge(c)
	if bytes.Equal(chalA.Seed, chalB.Seed) {
		t.Fatal("Challenge reused random seed")
	}
	for i := 0; i < m; i++ {
		assertUniqueInRange(t, chalA.Indices[i], c, n)
		assertUniqueInRange(t, chalB.Indices[i], c, n)
	}
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
