package pdpbatch

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
)

type SingleProof struct {
	Index    int
	Siblings [][]byte
}

type NodeKey struct {
	Level    int
	Position int
}

type MultiProof struct {
	Depth      int
	ProofNodes map[NodeKey][]byte
}

// NodeCount 返回多重证明中显式携带的兄弟节点数量，用于估算证明大小。
func (p MultiProof) NodeCount() int {
	return len(p.ProofNodes)
}

type MerkleTree struct {
	ActualLeafCount int
	Size            int
	EmptyLeaf       []byte
	Levels          [][][]byte
	Root            []byte

	counter *OperationCounter
}

// NewMerkleTree 用给定叶子构造二叉 Merkle 树，并把叶子数量补齐到 2 的幂。
func NewMerkleTree(leaves [][]byte, counter *OperationCounter, emptyLeaf []byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("merkle tree requires at least one leaf")
	}
	if emptyLeaf == nil {
		emptyLeaf = stableHashBytes(counter, "pad-leaf")
	}

	size := nextPowerOfTwo(len(leaves))
	padded := make([][]byte, 0, size)
	for _, leaf := range leaves {
		padded = append(padded, cloneBytes(leaf))
	}
	for len(padded) < size {
		padded = append(padded, cloneBytes(emptyLeaf))
	}

	levels := [][][]byte{padded}
	current := padded
	for len(current) > 1 {
		next := make([][]byte, 0, len(current)/2)
		for i := 0; i < len(current); i += 2 {
			next = append(next, stableHashBytes(counter, "merkle-node", current[i], current[i+1]))
		}
		levels = append(levels, next)
		current = next
	}

	return &MerkleTree{
		ActualLeafCount: len(leaves),
		Size:            size,
		EmptyLeaf:       cloneBytes(emptyLeaf),
		Levels:          levels,
		Root:            cloneBytes(levels[len(levels)-1][0]),
		counter:         counter,
	}, nil
}

// Depth 返回 Merkle 树从叶子层到根节点之间的层数。
func (t *MerkleTree) Depth() int {
	return len(t.Levels) - 1
}

// SingleProof 为单个叶子生成传统 Merkle 路径证明。
func (t *MerkleTree) SingleProof(index int) (SingleProof, error) {
	if index < 0 || index >= t.ActualLeafCount {
		return SingleProof{}, fmt.Errorf("leaf index %d out of range", index)
	}

	siblings := make([][]byte, 0, t.Depth())
	position := index
	for level := 0; level < t.Depth(); level++ {
		siblingPosition := position ^ 1
		siblings = append(siblings, cloneBytes(t.Levels[level][siblingPosition]))
		position /= 2
	}
	return SingleProof{Index: index, Siblings: siblings}, nil
}

// MultiProof 为多个叶子生成合并后的 Merkle 证明，避免重复携带共享路径节点。
func (t *MerkleTree) MultiProof(indices []int) (MultiProof, error) {
	indexSet := make(map[int]struct{}, len(indices))
	for _, index := range indices {
		if index < 0 || index >= t.ActualLeafCount {
			return MultiProof{}, fmt.Errorf("leaf index %d out of range", index)
		}
		indexSet[index] = struct{}{}
	}
	if len(indexSet) == 0 {
		return MultiProof{}, errors.New("multi proof requires at least one index")
	}

	currentPositions := indexSet
	proofNodes := make(map[NodeKey][]byte)
	for level := 0; level < t.Depth(); level++ {
		positions := sortedKeys(currentPositions)
		nextPositions := make(map[int]struct{})
		for _, position := range positions {
			sibling := position ^ 1
			if _, ok := currentPositions[sibling]; !ok {
				proofNodes[NodeKey{Level: level, Position: sibling}] = cloneBytes(t.Levels[level][sibling])
			}
			nextPositions[position/2] = struct{}{}
		}
		currentPositions = nextPositions
	}

	return MultiProof{Depth: t.Depth(), ProofNodes: proofNodes}, nil
}

// VerifySingle 根据叶子哈希和单路径证明重建根节点，并与期望根比较。
func VerifySingle(leafHash []byte, proof SingleProof, expectedRoot []byte, counter *OperationCounter) bool {
	current := cloneBytes(leafHash)
	position := proof.Index
	for _, sibling := range proof.Siblings {
		if position%2 == 0 {
			current = stableHashBytes(counter, "merkle-node", current, sibling)
		} else {
			current = stableHashBytes(counter, "merkle-node", sibling, current)
		}
		position /= 2
	}
	return bytes.Equal(current, expectedRoot)
}

// VerifyMulti 根据多个叶子和合并证明逐层重建 Merkle 根。
func VerifyMulti(leafHashes map[int][]byte, proof MultiProof, expectedRoot []byte, counter *OperationCounter) bool {
	currentLevel := make(map[int][]byte, len(leafHashes))
	for index, hash := range leafHashes {
		currentLevel[index] = cloneBytes(hash)
	}

	for level := 0; level < proof.Depth; level++ {
		parentSet := make(map[int]struct{})
		for position := range currentLevel {
			parentSet[position/2] = struct{}{}
		}

		nextLevel := make(map[int][]byte, len(parentSet))
		for _, parentPosition := range sortedKeys(parentSet) {
			leftPosition := 2 * parentPosition
			rightPosition := leftPosition + 1

			leftHash, ok := currentLevel[leftPosition]
			if !ok {
				leftHash, ok = proof.ProofNodes[NodeKey{Level: level, Position: leftPosition}]
			}
			if !ok {
				return false
			}

			rightHash, ok := currentLevel[rightPosition]
			if !ok {
				rightHash, ok = proof.ProofNodes[NodeKey{Level: level, Position: rightPosition}]
			}
			if !ok {
				return false
			}

			nextLevel[parentPosition] = stableHashBytes(counter, "merkle-node", leftHash, rightHash)
		}
		currentLevel = nextLevel
	}

	root, ok := currentLevel[0]
	return ok && bytes.Equal(root, expectedRoot)
}

// sortedKeys 返回 map 中按升序排列的键，保证证明生成和验证过程可复现。
func sortedKeys(values map[int]struct{}) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}

// cloneBytes 返回字节切片副本，避免调用方共享内部可变内存。
func cloneBytes(value []byte) []byte {
	out := make([]byte, len(value))
	copy(out, value)
	return out
}
