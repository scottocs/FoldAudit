package foldaudit

import (
	"bytes"
	"errors"
	"fmt"
)

type MerkleProof struct {
	Index    int
	Siblings [][]byte
}

type MerkleTree struct {
	LeafCount int
	Size      int
	Levels    [][][]byte
	Root      []byte
}

func NewMerkleTree(leaves [][]byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle tree requires at least one leaf")
	}

	size := nextPowerOfTwo(len(leaves))
	padded := make([][]byte, 0, size)
	for _, leaf := range leaves {
		padded = append(padded, cloneBytes(leaf))
	}
	padLeaf := hashBytes("foldaudit:merkle:pad")
	for len(padded) < size {
		padded = append(padded, cloneBytes(padLeaf))
	}

	levels := [][][]byte{padded}
	current := padded
	for len(current) > 1 {
		next := make([][]byte, 0, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			next = append(next, hashBytes("foldaudit:merkle:node", current[i], current[i+1]))
		}
		levels = append(levels, next)
		current = next
	}

	return &MerkleTree{
		LeafCount: len(leaves),
		Size:      size,
		Levels:    levels,
		Root:      cloneBytes(levels[len(levels)-1][0]),
	}, nil
}

func (t *MerkleTree) Proof(index int) (MerkleProof, error) {
	if t == nil {
		return MerkleProof{}, errors.New("merkle tree is nil")
	}
	if index < 0 || index >= t.LeafCount {
		return MerkleProof{}, fmt.Errorf("leaf index %d out of range", index)
	}

	siblings := make([][]byte, 0, len(t.Levels)-1)
	position := index
	for level := 0; level < len(t.Levels)-1; level++ {
		sibling := position ^ 1
		siblings = append(siblings, cloneBytes(t.Levels[level][sibling]))
		position /= 2
	}
	return MerkleProof{Index: index, Siblings: siblings}, nil
}

func VerifyMerkleProof(leaf, root []byte, proof MerkleProof) bool {
	current := cloneBytes(leaf)
	position := proof.Index
	for _, sibling := range proof.Siblings {
		if position%2 == 0 {
			current = hashBytes("foldaudit:merkle:node", current, sibling)
		} else {
			current = hashBytes("foldaudit:merkle:node", sibling, current)
		}
		position /= 2
	}
	return bytes.Equal(current, root)
}

func nextPowerOfTwo(value int) int {
	out := 1
	for out < value {
		out <<= 1
	}
	return out
}
