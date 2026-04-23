"""
Algebraic primitives for the batch-PDP protocol.

Paper symbol → Python entity mapping:
  Fp              → PrimeField
  G1 element g^x  → GroupElement(exponent=x)
  g^f(τ) (commit) → AlgebraicKZGBackend.commit_polynomial(f)
  g^s   (scalar)  → AlgebraicKZGBackend.commit_scalar(s)
  e(·,·) pairing  → AlgebraicKZGBackend.pairing(left, right_exp)
  H  (homomorphic)→ AlgebraicKZGBackend.commit_scalar  (H(m) = g^m)
  H1 (Merkle)     → stable_hash_bytes  (SHA-256 based)
  H2 (Fiat-Shamir)→ hash_to_field      (SHA-256 → Fp element)
  SRS             → implicitly encoded via tau in AlgebraicKZGBackend
"""
from __future__ import annotations

import hashlib
import json
import math
import random
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


@dataclass
class OperationCounter:
    hashes: int = 0
    exponentiations: int = 0
    group_multiplications: int = 0
    pairings: int = 0
    field_ops: int = 0

    def snapshot(self) -> dict[str, int]:
        return {
            "hashes": self.hashes,
            "exponentiations": self.exponentiations,
            "group_multiplications": self.group_multiplications,
            "pairings": self.pairings,
            "field_ops": self.field_ops,
        }

    @staticmethod
    def diff(after: dict[str, int], before: dict[str, int]) -> dict[str, int]:
        return {key: after[key] - before[key] for key in after}


class PrimeField:
    def __init__(self, modulus: int, counter: OperationCounter | None = None) -> None:
        if modulus <= 2:
            raise ValueError("modulus must be an odd prime")
        self.modulus = modulus
        self.counter = counter or OperationCounter()
        self.byte_length = math.ceil(modulus.bit_length() / 8)

    def normalize(self, value: int) -> int:
        return value % self.modulus

    def add(self, left: int, right: int) -> int:
        self.counter.field_ops += 1
        return (left + right) % self.modulus

    def sub(self, left: int, right: int) -> int:
        self.counter.field_ops += 1
        return (left - right) % self.modulus

    def mul(self, left: int, right: int) -> int:
        self.counter.field_ops += 1
        return (left * right) % self.modulus

    def inv(self, value: int) -> int:
        self.counter.field_ops += 1
        return pow(value, -1, self.modulus)

    def div(self, numerator: int, denominator: int) -> int:
        self.counter.field_ops += 1
        return self.mul(numerator, self.inv(denominator))

    def random(self, rng: random.Random, nonzero: bool = False) -> int:
        if nonzero:
            return rng.randrange(1, self.modulus)
        return rng.randrange(0, self.modulus)


class Polynomial:
    def __init__(self, coeffs: Sequence[int], field: PrimeField) -> None:
        self.field = field
        self.coeffs = [field.normalize(value) for value in coeffs]
        self._trim()

    def _trim(self) -> None:
        while len(self.coeffs) > 1 and self.coeffs[-1] == 0:
            self.coeffs.pop()

    @property
    def degree(self) -> int:
        return len(self.coeffs) - 1

    def evaluate(self, point: int) -> int:
        result = 0
        for coeff in reversed(self.coeffs):
            result = self.field.mul(result, point)
            result = self.field.add(result, coeff)
        return result

    def add(self, other: "Polynomial") -> "Polynomial":
        size = max(len(self.coeffs), len(other.coeffs))
        result = []
        for index in range(size):
            left = self.coeffs[index] if index < len(self.coeffs) else 0
            right = other.coeffs[index] if index < len(other.coeffs) else 0
            result.append(self.field.add(left, right))
        return Polynomial(result, self.field)

    def scale(self, scalar: int) -> "Polynomial":
        return Polynomial([self.field.mul(coeff, scalar) for coeff in self.coeffs], self.field)

    def subtract_constant(self, constant: int) -> "Polynomial":
        coeffs = list(self.coeffs)
        coeffs[0] = self.field.sub(coeffs[0], constant)
        return Polynomial(coeffs, self.field)

    def divide_by_linear(self, root: int) -> tuple["Polynomial", int]:
        if len(self.coeffs) == 1:
            return Polynomial([0], self.field), self.coeffs[0]
        quotient = [0] * (len(self.coeffs) - 1)
        carry = self.coeffs[-1]
        for index in range(len(self.coeffs) - 2, -1, -1):
            quotient[index] = carry
            carry = self.field.add(self.coeffs[index], self.field.mul(root, carry))
        remainder = carry
        return Polynomial(quotient, self.field), remainder

    def to_jsonable(self) -> list[int]:
        return list(self.coeffs)


@dataclass(frozen=True)
class GroupElement:
    exponent: int
    backend: "AlgebraicKZGBackend"

    def __mul__(self, other: "GroupElement") -> "GroupElement":
        if self.backend is not other.backend:
            raise ValueError("group elements must share the same backend")
        self.backend.counter.group_multiplications += 1
        exponent = (self.exponent + other.exponent) % self.backend.field.modulus
        return GroupElement(exponent, self.backend)

    def __pow__(self, scalar: int) -> "GroupElement":
        self.backend.counter.exponentiations += 1
        exponent = (self.exponent * scalar) % self.backend.field.modulus
        return GroupElement(exponent, self.backend)

    def serialize(self) -> bytes:
        return int(self.exponent).to_bytes(self.backend.field.byte_length, byteorder="big")


class AlgebraicKZGBackend:
    """
    Algebraic simulation of the KZG polynomial commitment scheme.

    Real KZG uses elliptic-curve group operations on BLS12-381.
    This backend replaces group elements with their discrete-log exponents,
    which preserves the algebraic structure used by the PDP protocol.

    SRS = (g, g^τ, g^τ², …, g^τ^(s-1), h, h^τ) is encoded via `tau`.
    Commitment: Cf = g^f(τ) = commit_polynomial(f)
    Pairing:    e(g^a, h^b) ≡ field.mul(a, b)   (GT is also Fp in simulation)
    """
    def __init__(self, field: PrimeField, tau: int, counter: OperationCounter | None = None) -> None:
        self.field = field
        self.tau = field.normalize(tau)
        self.counter = counter or field.counter

    def generator(self) -> GroupElement:
        return GroupElement(1, self)

    def identity(self) -> GroupElement:
        return GroupElement(0, self)

    def commit_scalar(self, scalar: int) -> GroupElement:
        self.counter.exponentiations += 1
        return GroupElement(self.field.normalize(scalar), self)

    def commit_polynomial(self, polynomial: Polynomial) -> GroupElement:
        self.counter.exponentiations += 1
        return GroupElement(polynomial.evaluate(self.tau), self)

    def pairing(self, left: GroupElement, right_exponent: int) -> int:
        self.counter.pairings += 1
        return self.field.mul(left.exponent, right_exponent)


def next_power_of_two(value: int) -> int:
    result = 1
    while result < value:
        result <<= 1
    return result


def _jsonable(value: Any) -> Any:
    if isinstance(value, GroupElement):
        return {"group_exp": value.exponent}
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Polynomial):
        return value.to_jsonable()
    if isinstance(value, dict):
        return {str(key): _jsonable(val) for key, val in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def stable_hash_bytes(counter: OperationCounter, *parts: Any) -> bytes:
    payload = json.dumps([_jsonable(part) for part in parts], sort_keys=True, separators=(",", ":")).encode("utf-8")
    counter.hashes += 1
    return hashlib.sha256(payload).digest()


def hash_to_field(field: PrimeField, counter: OperationCounter, label: str, *parts: Any) -> int:
    digest = stable_hash_bytes(counter, label, *parts)
    return int.from_bytes(digest, byteorder="big") % field.modulus


def product(elements: Iterable[GroupElement], backend: AlgebraicKZGBackend) -> GroupElement:
    result = backend.identity()
    for element in elements:
        result = result * element
    return result
