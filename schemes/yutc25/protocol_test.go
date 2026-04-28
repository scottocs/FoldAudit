package yutc25

import (
	"bytes"
	"math/big"
	"testing"

	"foldaudit/schemes/benchcore"
)

func TestProveDoesNotUseTrapdoor(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := NewProtocol(n, s)
	stored, err := p.StoreBatch(testDataset(m, n, s, "yu/no-trapdoor"))
	if err != nil {
		t.Fatal(err)
	}
	chal := p.BatchChallenge(m, c)

	p.psi = nil

	proof, err := p.ProveBatch(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.VerifyBatch(stored, chal, proof) {
		t.Fatal("honest proof generated without trapdoor was rejected")
	}
}

func TestChallengeUsesFreshRandomKeys(t *testing.T) {
	p := NewProtocol(32, 4)
	chalA := p.Challenge(8)
	chalB := p.Challenge(8)
	if bytes.Equal(chalA.K1, chalB.K1) || bytes.Equal(chalA.K2, chalB.K2) {
		t.Fatal("Challenge reused random keys")
	}
	assertUniqueInRange(t, chalA.Indices, 8, p.N)
	assertUniqueInRange(t, chalB.Indices, 8, p.N)
}

func TestBatchChallengeUsesFreshRandomKeysPerFile(t *testing.T) {
	p := NewProtocol(32, 4)
	chal := p.BatchChallenge(3, 8)
	if len(chal.FileChallenges) != 3 {
		t.Fatal("batch challenge file count mismatch")
	}
	for i, fileChal := range chal.FileChallenges {
		assertUniqueInRange(t, fileChal.Indices, 8, p.N)
		if i > 0 && bytes.Equal(chal.FileChallenges[i-1].K1, fileChal.K1) {
			t.Fatal("BatchChallenge reused challenge keys across files")
		}
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
