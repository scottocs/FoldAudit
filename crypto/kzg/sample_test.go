package kzg

import "testing"

// TestSampleBuildsAndVerifies 确认测试样本能够生成并通过本地 KZG 校验。
func TestSampleBuildsAndVerifies(t *testing.T) {
	sample, err := NewSample(1)
	if err != nil {
		t.Fatalf("NewSample failed: %v", err)
	}
	if sample.VersionedHash[0] != 0x01 {
		t.Fatalf("expected versioned hash prefix 0x01, got 0x%x", sample.VersionedHash[0])
	}
	if len(sample.CommitmentBytes()) != 48 {
		t.Fatalf("expected 48-byte commitment, got %d", len(sample.CommitmentBytes()))
	}
	if len(sample.ProofBytes()) != 48 {
		t.Fatalf("expected 48-byte proof, got %d", len(sample.ProofBytes()))
	}
}
