package miaoscis2026

import (
	"bytes"
	"math/big"
	"testing"

	"foldaudit/schemes/benchcore"
)

func TestChallengeWithTrapdoorUsesFreshRandomKeys(t *testing.T) {
	n, c := 32, 8
	p := NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: testScalars(n, "miao/random/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: testScalars(n, "miao/random/f1")},
		{FID: "f2", Keywords: []string{"cloud"}, Blocks: testScalars(n, "miao/random/f2")},
	}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		t.Fatal(err)
	}

	chalA := p.ChallengeWithTrapdoor(trap, c, len(files))
	chalB := p.ChallengeWithTrapdoor(trap, c, len(files))
	if bytes.Equal(chalA.K1, chalB.K1) || bytes.Equal(chalA.K2, chalB.K2) {
		t.Fatal("ChallengeWithTrapdoor reused random keys")
	}
	assertUniqueInRange(t, chalA.Indices, c, n)
	assertUniqueInRange(t, chalB.Indices, c, n)
}

func testScalars(n int, label string) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = benchcore.Scalar(label, i)
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
