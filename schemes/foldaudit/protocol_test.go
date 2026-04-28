package foldaudit

import (
	"bytes"
	"io"
	"testing"

	"foldaudit/schemes/benchcore"
)

type deterministicReader struct {
	state uint64
}

func newDeterministicReader(seed uint64) io.Reader {
	return &deterministicReader{state: seed}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		r.state = r.state*6364136223846793005 + 1442695040888963407
		p[i] = byte(r.state >> 56)
	}
	return len(p), nil
}

func testProtocol(t *testing.T, seed uint64) *Protocol {
	t.Helper()
	cfg := DefaultConfig()
	cfg.NumFiles = 3
	cfg.ChunksPerFile = 16
	cfg.SectorsPerChunk = 4
	cfg.ChallengedChunks = 4

	protocol, err := Setup(cfg, newDeterministicReader(seed))
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	return protocol
}

func TestHonestFoldAuditRoundAccepts(t *testing.T) {
	protocol := testProtocol(t, 11)
	data, err := protocol.RandomDataset()
	if err != nil {
		t.Fatalf("RandomDataset failed: %v", err)
	}
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if !protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify rejected honest proof")
	}
}

func TestTamperedProofFieldsAreRejected(t *testing.T) {
	protocol := testProtocol(t, 12)
	data, _ := protocol.RandomDataset()
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}
	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if !protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify rejected honest proof")
	}

	tamperedY := cloneProof(proof)
	tamperedY.FileProofs[0].YTilde = benchcore.Add(tamperedY.FileProofs[0].YTilde, benchcore.One())
	if protocol.Verify(stored, chal, tamperedY) {
		t.Fatal("Verify accepted tampered masked evaluation")
	}

	tamperedCw := cloneProof(proof)
	tamperedCw.FileProofs[0].Cw = benchcore.G1Add(tamperedCw.FileProofs[0].Cw, benchcore.G1Base(benchcore.One()))
	if protocol.Verify(stored, chal, tamperedCw) {
		t.Fatal("Verify accepted tampered quotient commitment")
	}
}

func TestTamperedChallengedDataWithOldTagsIsRejected(t *testing.T) {
	protocol := testProtocol(t, 13)
	data, _ := protocol.RandomDataset()
	stored, err := protocol.Store(data)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}
	chal, err := protocol.Challenge()
	if err != nil {
		t.Fatalf("Challenge failed: %v", err)
	}

	chunk := chal.Indices[0]
	stored.Files[0].Sectors[chunk][0] = benchcore.Add(stored.Files[0].Sectors[chunk][0], benchcore.One())
	stored.Files[0].Polynomials[chunk] = benchcore.NewPoly(stored.Files[0].Sectors[chunk])

	proof, err := protocol.ProofGen(stored, chal)
	if err != nil {
		t.Fatalf("ProofGen failed: %v", err)
	}
	if protocol.Verify(stored, chal, proof) {
		t.Fatal("Verify accepted proof generated from data inconsistent with authenticated tags")
	}
}

func TestMerkleLeafBindsFileAndPosition(t *testing.T) {
	tag := benchcore.G1Base(benchcore.One())
	leafA := merkleLeaf([]byte("file-a"), 0, tag)
	leafB := merkleLeaf([]byte("file-b"), 0, tag)
	leafC := merkleLeaf([]byte("file-a"), 1, tag)
	if bytes.Equal(leafA, leafB) || bytes.Equal(leafA, leafC) {
		t.Fatal("merkle leaf does not bind file id and chunk index")
	}
}

func cloneProof(proof *AuditProof) *AuditProof {
	out := &AuditProof{
		FileProofs: make([]FileProof, len(proof.FileProofs)),
		PiR:        make([]SchnorrProof, len(proof.PiR)),
	}
	for i, fp := range proof.FileProofs {
		auth := make([]TagProof, len(fp.Auth))
		for j, tagProof := range fp.Auth {
			siblings := make([][]byte, len(tagProof.Path.Siblings))
			for k, sibling := range tagProof.Path.Siblings {
				siblings[k] = benchcore.CloneBytes(sibling)
			}
			auth[j] = TagProof{
				Index: tagProof.Index,
				Tag:   cloneG1(tagProof.Tag),
				Path: benchcore.MerkleProof{
					Index:    tagProof.Path.Index,
					Siblings: siblings,
				},
			}
		}
		out.FileProofs[i] = FileProof{
			Auth:   auth,
			YTilde: benchcore.Normalize(fp.YTilde),
			R:      cloneG1(fp.R),
			Cw:     cloneG1(fp.Cw),
			B:      cloneG1(fp.B),
		}
	}
	for i, pi := range proof.PiR {
		out.PiR[i] = SchnorrProof{A: cloneG1(pi.A), Z: benchcore.Normalize(pi.Z)}
	}
	return out
}
