package kzg

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto/kzg4844"
)

const (
	FieldElementsPerBlob = 4096
	FieldElementBytes    = 32
)

type Sample struct {
	Seed          uint64
	Blob          kzg4844.Blob
	Commitment    kzg4844.Commitment
	Point         kzg4844.Point
	Claim         kzg4844.Claim
	Proof         kzg4844.Proof
	VersionedHash [32]byte
}

func NewSample(seed uint64) (*Sample, error) {
	var blob kzg4844.Blob
	fillBlob(&blob, seed)

	commitment, err := kzg4844.BlobToCommitment(&blob)
	if err != nil {
		return nil, fmt.Errorf("blob to commitment: %w", err)
	}

	point := makePoint(seed*17 + 1)
	proof, claim, err := kzg4844.ComputeProof(&blob, point)
	if err != nil {
		return nil, fmt.Errorf("compute point proof: %w", err)
	}

	if err := kzg4844.VerifyProof(commitment, point, claim, proof); err != nil {
		return nil, fmt.Errorf("local verify proof: %w", err)
	}

	versionedHash := kzg4844.CalcBlobHashV1(sha256.New(), &commitment)
	return &Sample{
		Seed:          seed,
		Blob:          blob,
		Commitment:    commitment,
		Point:         point,
		Claim:         claim,
		Proof:         proof,
		VersionedHash: versionedHash,
	}, nil
}

func fillBlob(blob *kzg4844.Blob, seed uint64) {
	for i := 0; i < FieldElementsPerBlob; i++ {
		offset := i * FieldElementBytes
		value := seed + uint64(i) + 1
		binary.BigEndian.PutUint64(blob[offset+24:offset+32], value)
	}
}

func makePoint(value uint64) kzg4844.Point {
	var point kzg4844.Point
	binary.BigEndian.PutUint64(point[24:], value)
	return point
}

func (s *Sample) CommitmentBytes() []byte {
	out := make([]byte, len(s.Commitment))
	copy(out, s.Commitment[:])
	return out
}

func (s *Sample) ProofBytes() []byte {
	out := make([]byte, len(s.Proof))
	copy(out, s.Proof[:])
	return out
}
