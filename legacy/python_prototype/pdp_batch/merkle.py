"""
Merkle tree with single-proof and multi-proof authentication.

Paper symbol → Python entity:
  H1(i‖j‖σi,j)   → stable_hash_bytes(counter, "tag-leaf", i, j, σ)
  H1(Nl ‖ Nr)     → stable_hash_bytes(counter, "merkle-node", left, right)
  Li,j (leaf)     → bytes produced by _merkle_leaf() in protocol.py
  Γi   (root)     → MerkleTree.root
  Authi (SP mode) → SingleProof  – c independent sibling paths
  Authi (MP mode) → MultiProof   – compressed Tag-IMHT multi-proof
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable

from .algebra import OperationCounter, next_power_of_two, stable_hash_bytes


@dataclass
class SingleProof:
    index: int
    siblings: list[bytes]


@dataclass
class MultiProof:
    depth: int
    proof_nodes: dict[tuple[int, int], bytes]

    @property
    def node_count(self) -> int:
        return len(self.proof_nodes)


class MerkleTree:
    def __init__(self, leaves: list[bytes], counter: OperationCounter, empty_leaf: bytes | None = None) -> None:
        if not leaves:
            raise ValueError("Merkle tree requires at least one leaf")
        self.counter = counter
        self.actual_leaf_count = len(leaves)
        self.size = next_power_of_two(len(leaves))
        self.empty_leaf = empty_leaf or stable_hash_bytes(counter, "pad-leaf")
        padded = list(leaves) + [self.empty_leaf] * (self.size - len(leaves))
        self.levels = [padded]
        current = padded
        while len(current) > 1:
            nxt = []
            for index in range(0, len(current), 2):
                nxt.append(stable_hash_bytes(counter, "merkle-node", current[index], current[index + 1]))
            self.levels.append(nxt)
            current = nxt
        self.root = self.levels[-1][0]

    @property
    def depth(self) -> int:
        return len(self.levels) - 1

    def single_proof(self, index: int) -> SingleProof:
        if index >= self.actual_leaf_count:
            raise IndexError("leaf index out of range")
        siblings: list[bytes] = []
        position = index
        for level in range(self.depth):
            sibling_position = position ^ 1
            siblings.append(self.levels[level][sibling_position])
            position //= 2
        return SingleProof(index=index, siblings=siblings)

    def multi_proof(self, indices: Iterable[int]) -> MultiProof:
        index_set = sorted(set(indices))
        if not index_set:
            raise ValueError("multi proof requires at least one index")
        current_positions = set(index_set)
        proof_nodes: dict[tuple[int, int], bytes] = {}
        for level in range(self.depth):
            next_positions = set()
            for position in sorted(current_positions):
                sibling = position ^ 1
                if sibling not in current_positions:
                    proof_nodes[(level, sibling)] = self.levels[level][sibling]
                next_positions.add(position // 2)
            current_positions = next_positions
        return MultiProof(depth=self.depth, proof_nodes=proof_nodes)

    @staticmethod
    def verify_single(leaf_hash: bytes, proof: SingleProof, expected_root: bytes, counter: OperationCounter) -> bool:
        current = leaf_hash
        position = proof.index
        for sibling in proof.siblings:
            if position % 2 == 0:
                current = stable_hash_bytes(counter, "merkle-node", current, sibling)
            else:
                current = stable_hash_bytes(counter, "merkle-node", sibling, current)
            position //= 2
        return current == expected_root

    @staticmethod
    def verify_multi(
        leaf_hashes: Dict[int, bytes],
        proof: MultiProof,
        expected_root: bytes,
        counter: OperationCounter,
    ) -> bool:
        current_level = dict(leaf_hashes)
        for level in range(proof.depth):
            parent_positions = sorted({position // 2 for position in current_level})
            next_level: dict[int, bytes] = {}
            for parent_position in parent_positions:
                left_position = 2 * parent_position
                right_position = left_position + 1
                left_hash = current_level.get(left_position, proof.proof_nodes.get((level, left_position)))
                right_hash = current_level.get(right_position, proof.proof_nodes.get((level, right_position)))
                if left_hash is None or right_hash is None:
                    return False
                next_level[parent_position] = stable_hash_bytes(counter, "merkle-node", left_hash, right_hash)
            current_level = next_level
        return current_level.get(0) == expected_root
