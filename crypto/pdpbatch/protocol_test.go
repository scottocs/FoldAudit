package pdpbatch

import "testing"

// TestHonestRoundAcceptsForSingleAndMultiProofs 确认诚实数据在单路径和多重证明模式下都能通过验证。
func TestHonestRoundAcceptsForSingleAndMultiProofs(t *testing.T) {
	config := DefaultProtocolConfig()
	config.NumFiles = 3
	config.ChunksPerFile = 16
	config.SectorsPerChunk = 4
	config.ChallengedChunks = 4
	config.RNGSeed = 21

	protocol, err := NewBatchPDPProtocol(config)
	if err != nil {
		t.Fatalf("NewBatchPDPProtocol failed: %v", err)
	}

	dataset := protocol.RandomFileBatch()
	storedBatch, err := protocol.Store(dataset)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	challenge := protocol.Challenge()

	for _, authMode := range []AuthMode{AuthModeSP, AuthModeMP} {
		proof, err := protocol.ProofGen(storedBatch, challenge, authMode)
		if err != nil {
			t.Fatalf("ProofGen(%s) failed: %v", authMode, err)
		}
		if !protocol.Verify(storedBatch, challenge, proof) {
			t.Fatalf("Verify rejected honest %s proof", authMode)
		}
	}
}

// TestTamperedChallengedDataIsDetected 确认被挑战数据遭篡改后会被验证流程拒绝。
func TestTamperedChallengedDataIsDetected(t *testing.T) {
	config := DefaultProtocolConfig()
	config.NumFiles = 2
	config.ChunksPerFile = 16
	config.SectorsPerChunk = 4
	config.ChallengedChunks = 4
	config.RNGSeed = 22

	protocol, err := NewBatchPDPProtocol(config)
	if err != nil {
		t.Fatalf("NewBatchPDPProtocol failed: %v", err)
	}

	dataset := protocol.RandomFileBatch()
	storedBatch, err := protocol.Store(dataset)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	challenge := protocol.Challenge()

	tamperedBatch := protocol.CloneStoredBatch(storedBatch)
	if err := protocol.TamperChallengedSector(tamperedBatch, challenge); err != nil {
		t.Fatalf("TamperChallengedSector failed: %v", err)
	}
	tamperedProof, err := protocol.ProofGen(tamperedBatch, challenge, AuthModeMP)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if protocol.Verify(tamperedBatch, challenge, tamperedProof) {
		t.Fatal("Verify accepted tampered challenged data")
	}
}

// TestMultiProofUsesFewerOrEqualHashNodesThanSinglePaths 比较多重证明和单路径证明携带的哈希节点数量。
func TestMultiProofUsesFewerOrEqualHashNodesThanSinglePaths(t *testing.T) {
	config := DefaultProtocolConfig()
	config.NumFiles = 2
	config.ChunksPerFile = 32
	config.SectorsPerChunk = 4
	config.ChallengedChunks = 8
	config.RNGSeed = 23

	protocol, err := NewBatchPDPProtocol(config)
	if err != nil {
		t.Fatalf("NewBatchPDPProtocol failed: %v", err)
	}

	dataset := protocol.RandomFileBatch()
	storedBatch, err := protocol.Store(dataset)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	challenge := protocol.Challenge()

	proofSP, err := protocol.ProofGen(storedBatch, challenge, AuthModeSP)
	if err != nil {
		t.Fatalf("ProofGen(sp) failed: %v", err)
	}
	proofMP, err := protocol.ProofGen(storedBatch, challenge, AuthModeMP)
	if err != nil {
		t.Fatalf("ProofGen(mp) failed: %v", err)
	}

	sizesSP := protocol.SizeReport(challenge, proofSP)
	sizesMP := protocol.SizeReport(challenge, proofMP)
	if sizesMP["auth_hash_nodes"] > sizesSP["auth_hash_nodes"] {
		t.Fatalf("multi proof used more auth nodes: mp=%d sp=%d", sizesMP["auth_hash_nodes"], sizesSP["auth_hash_nodes"])
	}
}
