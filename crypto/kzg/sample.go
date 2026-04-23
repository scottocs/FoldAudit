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

// NewSample 基于给定种子构造可复现的 EIP-4844 KZG 样本，并在本地先完成一次证明校验。
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

// fillBlob 用种子填充 blob 中的每个域元素位置，生成确定性的测试数据。
func fillBlob(blob *kzg4844.Blob, seed uint64) {
	for i := 0; i < FieldElementsPerBlob; i++ {
		offset := i * FieldElementBytes
		value := seed + uint64(i) + 1
		binary.BigEndian.PutUint64(blob[offset+24:offset+32], value)
	}
}

// makePoint 将 uint64 写入 32 字节评估点末尾，生成简单可复现的 KZG 评估点。
func makePoint(value uint64) kzg4844.Point {
	var point kzg4844.Point
	binary.BigEndian.PutUint64(point[24:], value)
	return point
}

// CommitmentBytes 返回承诺的字节副本，避免调用方意外修改 Sample 内部数据。
func (s *Sample) CommitmentBytes() []byte {
	out := make([]byte, len(s.Commitment))
	copy(out, s.Commitment[:])
	return out
}

// ProofBytes 返回证明的字节副本，供 ABI 编码或序列化使用。
func (s *Sample) ProofBytes() []byte {
	out := make([]byte, len(s.Proof))
	copy(out, s.Proof[:])
	return out
}
