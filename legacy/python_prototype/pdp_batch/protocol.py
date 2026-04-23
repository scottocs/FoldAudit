"""
Batch-verifiable Provable Data Possession across multiple files.

Algorithm mapping (paper → this file):
  Algorithm 1  Setup    → BatchPDPProtocol.setup()
  Algorithm 2  Store    → BatchPDPProtocol.store()
  Algorithm 3  Chal     → BatchPDPProtocol.challenge()
  Algorithm 4  ProofGen → BatchPDPProtocol.proofgen()
  Algorithm 5  Verify   → BatchPDPProtocol.verify()
"""
from __future__ import annotations

import math
import random
import string
import time
from dataclasses import asdict, dataclass
from typing import Literal

from .algebra import (
    AlgebraicKZGBackend,
    GroupElement,
    OperationCounter,
    Polynomial,
    PrimeField,
    hash_to_field,
    stable_hash_bytes,
)
from .merkle import MerkleTree, MultiProof, SingleProof


AuthMode = Literal["sp", "mp"]


@dataclass
class ProtocolConfig:
    num_files: int = 4          # m: number of files
    chunks_per_file: int = 64   # n: chunks per file
    sectors_per_chunk: int = 8  # s: sectors per chunk
    challenged_chunks: int = 8  # c: challenged chunks per audit
    prime_modulus: int = 2_305_843_009_213_693_951
    field_bytes: int = 32
    group_bytes: int = 48
    hash_bytes: int = 32
    rng_seed: int = 7

    def validate(self) -> None:
        if self.num_files <= 0:
            raise ValueError("num_files must be positive")
        if self.chunks_per_file <= 0:
            raise ValueError("chunks_per_file must be positive")
        if self.sectors_per_chunk <= 0:
            raise ValueError("sectors_per_chunk must be positive")
        if not 0 < self.challenged_chunks <= self.chunks_per_file:
            raise ValueError("challenged_chunks must be in [1, chunks_per_file]")


# ---------------------------------------------------------------------------
# Storage data structures (output of Algorithm 2 Store)
# ---------------------------------------------------------------------------

@dataclass
class StoredFile:
    """Per-file data held by the Cloud Server after Algorithm 2 Store."""
    sectors: list[list[int]]      # mi,j,k – raw field elements
    polynomials: list[Polynomial]  # fi,j(X)
    tags: list[GroupElement]       # σi,j = g^fi,j(τ)
    merkle_tree: MerkleTree        # Merkle tree over {Li,j}


@dataclass
class StoredBatch:
    files: list[StoredFile]
    roots: list[bytes]            # {Γi} kept by DO / shared with Verifier


# ---------------------------------------------------------------------------
# Challenge (Algorithm 3 Chal)
# ---------------------------------------------------------------------------

@dataclass
class Challenge:
    """chal = (J, {vj}j∈J, {ri}i∈[m], nonce)"""
    indices: list[int]            # J ⊆ [n], |J| = c
    coefficients: dict[int, int]  # {vj} – random aggregation coefficients
    evaluation_points: list[int]  # {ri} – per-file evaluation points
    nonce: str

    def to_public_dict(self) -> dict[str, object]:
        return {
            "indices": self.indices,
            "coefficients": self.coefficients,
            "evaluation_points": self.evaluation_points,
            "nonce": self.nonce,
        }


# ---------------------------------------------------------------------------
# Proof data structures (output of Algorithm 4 ProofGen)
# ---------------------------------------------------------------------------

@dataclass
class AuthPayload:
    """Merkle authentication evidence for challenged chunks of one file (Ti, Authi)."""
    tags: dict[int, GroupElement]           # {σi,j}j∈J provided to verifier
    single_proofs: dict[int, SingleProof] | None = None  # SP mode: c independent paths
    multi_proof: MultiProof | None = None               # MP mode: one compressed proof


@dataclass
class FileProof:
    """Per-file proof components: (Ti, Authi, bi, ỹi, Ri)."""
    auth: AuthPayload   # Ti (tags) + Authi (Merkle proof)
    b: GroupElement     # bi = g^fi(τ) – aggregated tag
    y_tilde: int        # ỹi = yi + µi – masked evaluation
    R: GroupElement     # Ri = g^µi – masking commitment


@dataclass
class AuditProof:
    """
    Complete audit proof π returned by Algorithm 4 ProofGen:
      π = ( {Ti, Authi, bi, ỹi, Ri}i∈[m],  Cq, Cqr,  ṼQ, RQ,  πbatch )
    """
    auth_mode: AuthMode
    file_proofs: list[FileProof]  # {Ti, Authi, bi, ỹi, Ri} for i ∈ [m]
    Cq: GroupElement              # Cq  = g^q(τ)
    Cqr: GroupElement             # Cqr = g^(Σ ri·wi(τ))
    V_tilde_Q: int                # ṼQ  = VQ + η  (masked folded evaluation)
    RQ: GroupElement              # RQ  = g^η      (global masking commitment)
    pi_batch: GroupElement        # πbatch = g^((Q(τ)−VQ)/(τ−z))


# ---------------------------------------------------------------------------
# Protocol class
# ---------------------------------------------------------------------------

class BatchPDPProtocol:
    """
    Implements Algorithms 1–5 from the paper.

    Typical usage:
        pp = BatchPDPProtocol.setup(config)          # Algorithm 1
        stored = pp.store(dataset)                   # Algorithm 2
        chal   = pp.challenge()                      # Algorithm 3
        proof  = pp.proofgen(stored, chal)           # Algorithm 4
        ok     = pp.verify(stored, chal, proof)      # Algorithm 5
    """

    # ------------------------------------------------------------------
    # Algorithm 1 – Setup
    # ------------------------------------------------------------------

    @classmethod
    def setup(cls, config: ProtocolConfig | None = None) -> "BatchPDPProtocol":
        """
        Algorithm 1 Setup.

        Generates the bilinear group (G1, G2, GT, e) of prime order p,
        samples secret trapdoor τ ∈ Fp, builds the Structured Reference
        String (SRS), and fixes cryptographic hash functions H, H1, H2.
        Returns the initialised protocol object containing pp.
        """
        return cls(config or ProtocolConfig())

    def __init__(self, config: ProtocolConfig) -> None:
        """Internal initialisation – use BatchPDPProtocol.setup() from outside."""
        config.validate()
        self.config = config
        self.counter = OperationCounter()
        # Fp with prime order p – corresponds to paper's prime field
        self.field = PrimeField(config.prime_modulus, self.counter)
        self.rng = random.Random(config.rng_seed)
        # Secret trapdoor τ ← Fp (SRS is defined by τ in the algebraic backend)
        tau = self.field.random(self.rng, nonzero=True)
        # Algebraic KZG backend encodes (G1, G2, GT, e, SRS)
        self.backend = AlgebraicKZGBackend(self.field, tau, self.counter)
        # Public generator g ∈ G1
        self.g = self.backend.generator()

    # ------------------------------------------------------------------
    # Data generation helper (testing only)
    # ------------------------------------------------------------------

    def random_file_batch(self) -> list[list[list[int]]]:
        """Generate a random dataset of m files, each with n chunks of s sectors."""
        dataset = []
        for _ in range(self.config.num_files):
            file_chunks = []
            for _ in range(self.config.chunks_per_file):
                sectors = [self.field.random(self.rng) for _ in range(self.config.sectors_per_chunk)]
                file_chunks.append(sectors)
            dataset.append(file_chunks)
        return dataset

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _chunk_polynomial(self, sectors: list[int]) -> Polynomial:
        """fi,j(X) = Σk mi,j,k · X^k"""
        return Polynomial(sectors, self.field)

    def _merkle_leaf(self, file_index: int, chunk_index: int, tag: GroupElement) -> bytes:
        """Li,j = H1(i ‖ j ‖ σi,j)  (Algorithm 2, line 5)."""
        return stable_hash_bytes(self.counter, "tag-leaf", file_index, chunk_index, tag.serialize())

    def _aggregate_polynomial(self, stored_file: StoredFile, challenge: Challenge) -> Polynomial:
        """fi(X) = Σj∈J vj · fi,j(X)  (Algorithm 4, line 2)."""
        poly = Polynomial([0], self.field)
        for j in challenge.indices:
            poly = poly.add(stored_file.polynomials[j].scale(challenge.coefficients[j]))
        return poly

    def _aggregate_tag(self, stored_file: StoredFile, challenge: Challenge) -> GroupElement:
        """bi = Πj∈J σi,j^vj = g^fi(τ)  (Algorithm 4, line 3)."""
        result = self.backend.identity()
        for j in challenge.indices:
            result = result * (stored_file.tags[j] ** challenge.coefficients[j])
        return result

    def _build_auth_payload(self, stored_file: StoredFile, challenge: Challenge, auth_mode: AuthMode) -> AuthPayload:
        """
        Build Authi: Merkle authentication path(s) for challenged chunks.
        SP mode: c independent single-proof paths.
        MP mode: one compressed multi-proof (Tag-IMHT).
        """
        tags = {j: stored_file.tags[j] for j in challenge.indices}
        if auth_mode == "sp":
            single_proofs = {j: stored_file.merkle_tree.single_proof(j) for j in challenge.indices}
            return AuthPayload(tags=tags, single_proofs=single_proofs)
        multi_proof = stored_file.merkle_tree.multi_proof(challenge.indices)
        return AuthPayload(tags=tags, multi_proof=multi_proof)

    def _fiat_shamir_alpha(
        self,
        challenge: Challenge,
        roots: list[bytes],
        file_proofs: list[FileProof],
        Cq: GroupElement,
        Cqr: GroupElement,
        file_index: int,
    ) -> int:
        """
        αi ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, i)
        Algorithm 4 line 13 / Algorithm 5 line 13.
        """
        bundle = [{"b": fp.b, "y_tilde": fp.y_tilde, "R": fp.R} for fp in file_proofs]
        return hash_to_field(
            self.field,
            self.counter,
            "alpha",
            challenge.to_public_dict(),
            roots,
            bundle,
            Cq,
            Cqr,
            file_index,
        )

    def _fiat_shamir_z(
        self,
        challenge: Challenge,
        roots: list[bytes],
        file_proofs: list[FileProof],
        Cq: GroupElement,
        Cqr: GroupElement,
        CQ: GroupElement,
    ) -> int:
        """
        z ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, CQ)
        Algorithm 4 line 17 / Algorithm 5 line 16.
        """
        bundle = [{"b": fp.b, "y_tilde": fp.y_tilde, "R": fp.R} for fp in file_proofs]
        return hash_to_field(
            self.field,
            self.counter,
            "z",
            challenge.to_public_dict(),
            roots,
            bundle,
            Cq,
            Cqr,
            CQ,
        )

    # ------------------------------------------------------------------
    # Algorithm 2 – Store
    # ------------------------------------------------------------------

    def store(self, dataset: list[list[list[int]]]) -> StoredBatch:
        """
        Algorithm 2 Store.

        For each file Fi (i ∈ [m]), encodes chunks as polynomials fi,j(X),
        computes KZG tags σi,j = g^fi,j(τ), builds a Merkle tree over the
        leaf hashes Li,j = H1(i ‖ j ‖ σi,j), and returns the stored batch.
        The Merkle roots {Γi} are retained by the DO and shared with V.
        """
        stored_files: list[StoredFile] = []
        roots: list[bytes] = []

        for i, file_chunks in enumerate(dataset):           # line 1: for i = 1 to m
            polynomials: list[Polynomial] = []
            tags: list[GroupElement] = []
            leaves: list[bytes] = []

            for j, sectors in enumerate(file_chunks):       # line 2: for j = 1 to n
                fi_j = self._chunk_polynomial(sectors)      # line 3: parse chunk → fi,j(X)
                sigma_i_j = self.backend.commit_polynomial(fi_j)  # line 4: σi,j = g^fi,j(τ)
                L_i_j = self._merkle_leaf(i, j, sigma_i_j)        # line 5: Li,j = H1(i‖j‖σi,j)
                polynomials.append(fi_j)
                tags.append(sigma_i_j)
                leaves.append(L_i_j)
                                                            # line 6: end for
            tree = MerkleTree(leaves, self.counter)         # line 7: build Merkle tree
            Gamma_i = tree.root                             # line 8: Γi = root

            stored_files.append(StoredFile(file_chunks, polynomials, tags, tree))
            roots.append(Gamma_i)
                                                            # line 9: end for
        # line 10: DO sends (Fi, {σi,j}) to CS and records {Γi} for V
        return StoredBatch(files=stored_files, roots=roots)

    # ------------------------------------------------------------------
    # Algorithm 3 – Chal
    # ------------------------------------------------------------------

    def challenge(self) -> Challenge:
        """
        Algorithm 3 Chal.

        Samples a shared challenged index set J ⊆ [n] with |J| = c,
        random aggregation coefficients {vj} ← Fp, per-file evaluation
        points {ri} ← Fp, and a fresh nonce.
        Returns chal = (J, {vj}j∈J, {ri}i∈[m], nonce).
        """
        # line 1: sample J ⊆ [n], |J| = c
        J = sorted(self.rng.sample(range(self.config.chunks_per_file), self.config.challenged_chunks))
        # line 2: {vj} ← Fp
        v = {j: self.field.random(self.rng, nonzero=True) for j in J}
        # line 3: {ri} ← Fp
        r = [self.field.random(self.rng) for _ in range(self.config.num_files)]
        # line 4: chal = (J, {vj}, {ri}, nonce)
        nonce = "".join(self.rng.choice(string.ascii_letters + string.digits) for _ in range(16))
        return Challenge(indices=J, coefficients=v, evaluation_points=r, nonce=nonce)

    # ------------------------------------------------------------------
    # Algorithm 4 – ProofGen
    # ------------------------------------------------------------------

    def proofgen(self, stored_batch: StoredBatch, challenge: Challenge, auth_mode: AuthMode = "mp") -> AuditProof:
        """
        Algorithm 4 ProofGen.

        Returns proof π = ({Ti, Authi, bi, ỹi, Ri}i∈[m], Cq, Cqr, ṼQ, RQ, πbatch).
        """
        file_proofs: list[FileProof] = []
        fi_polys: list[Polynomial] = []   # fi(X) for each file
        wi_polys: list[Polynomial] = []   # wi(X) for each file
        # Accumulate Σ ri·wi(τ) for Cqr
        sum_ri_wi_tau = 0

        for i, stored_file in enumerate(stored_batch.files):      # line 1: for i = 1 to m
            ri = challenge.evaluation_points[i]

            # line 2: fi(X) ← Σj∈J vj·fi,j(X)
            fi = self._aggregate_polynomial(stored_file, challenge)
            # line 3: bi ← Πj∈J σi,j^vj = g^fi(τ)
            bi = self._aggregate_tag(stored_file, challenge)
            # line 4: yi ← fi(ri)
            yi = fi.evaluate(ri)
            # line 5: µi ← Fp,  ỹi ← yi + µi,  Ri ← g^µi
            mu_i = self.field.random(self.rng)
            y_tilde_i = self.field.add(yi, mu_i)
            Ri = self.backend.commit_scalar(mu_i)
            # line 6: build Authi for the ith Merkle tree
            auth_i = self._build_auth_payload(stored_file, challenge, auth_mode)
            # line 7: wi(X) ← (fi(X) − yi) / (X − ri)
            wi, remainder = fi.subtract_constant(yi).divide_by_linear(ri)
            if remainder != 0:
                raise ValueError(f"quotient remainder non-zero for file {i}")

            # Accumulate ri·wi(τ) for Cqr (line 11)
            wi_tau = wi.evaluate(self.backend.tau)
            sum_ri_wi_tau = self.field.add(sum_ri_wi_tau, self.field.mul(ri, wi_tau))

            fi_polys.append(fi)
            wi_polys.append(wi)
            file_proofs.append(FileProof(auth=auth_i, b=bi, y_tilde=y_tilde_i, R=Ri))
                                                                   # line 8: end for

        # line 9: q(X) ← Σi=1..m wi(X)
        q_poly = Polynomial([0], self.field)
        for wi in wi_polys:
            q_poly = q_poly.add(wi)

        # line 10: Cq ← g^q(τ)
        Cq = self.backend.commit_polynomial(q_poly)
        # line 11: Cqr ← Πi(g^wi(τ))^ri = g^(Σ ri·wi(τ))
        Cqr = self.backend.commit_scalar(sum_ri_wi_tau)

        # lines 12-14: αi ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, i)
        alphas = [
            self._fiat_shamir_alpha(challenge, stored_batch.roots, file_proofs, Cq, Cqr, i)
            for i in range(self.config.num_files)
        ]

        # line 15: Q(X) ← q(X) + Σi αi·fi(X)
        Q_poly = q_poly
        # line 16: CQ ← Cq · Πi bi^αi
        CQ = Cq
        for alpha_i, fi, fp in zip(alphas, fi_polys, file_proofs):
            Q_poly = Q_poly.add(fi.scale(alpha_i))
            CQ = CQ * (fp.b ** alpha_i)

        # line 17: z ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, CQ)
        z = self._fiat_shamir_z(challenge, stored_batch.roots, file_proofs, Cq, Cqr, CQ)

        # line 18: VQ ← Q(z)
        VQ = Q_poly.evaluate(z)

        # line 19: η ← Fp,  ṼQ ← VQ + η,  RQ ← g^η
        eta = self.field.random(self.rng)
        V_tilde_Q = self.field.add(VQ, eta)
        RQ = self.backend.commit_scalar(eta)

        # line 20: πbatch ← g^((Q(τ)−VQ)/(τ−z))
        pi_poly, remainder = Q_poly.subtract_constant(VQ).divide_by_linear(z)
        if remainder != 0:
            raise ValueError("opening quotient remainder non-zero")
        pi_batch = self.backend.commit_polynomial(pi_poly)

        # line 21: return π
        return AuditProof(
            auth_mode=auth_mode,
            file_proofs=file_proofs,
            Cq=Cq,
            Cqr=Cqr,
            V_tilde_Q=V_tilde_Q,
            RQ=RQ,
            pi_batch=pi_batch,
        )

    # ------------------------------------------------------------------
    # Algorithm 5 – Verify
    # ------------------------------------------------------------------

    def _verify_auth(
        self,
        file_index: int,
        root: bytes,
        file_proof: FileProof,
        challenge: Challenge,
        auth_mode: AuthMode,
    ) -> bool:
        """
        Algorithm 5 lines 2-6.
        Checks Merkle proof (Authi) and tag recombination b̂i == bi.
        """
        # Recompute leaf hashes for challenged indices
        leaf_hashes = {
            j: self._merkle_leaf(file_index, j, tag)
            for j, tag in file_proof.auth.tags.items()
        }
        # Verify Merkle authentication path
        if auth_mode == "sp":
            assert file_proof.auth.single_proofs is not None
            for j, sp in file_proof.auth.single_proofs.items():
                if not MerkleTree.verify_single(leaf_hashes[j], sp, root, self.counter):
                    return False
        else:
            assert file_proof.auth.multi_proof is not None
            if not MerkleTree.verify_multi(leaf_hashes, file_proof.auth.multi_proof, root, self.counter):
                return False

        # line 3: b̂i ← Πj∈J σi,j^vj
        b_hat_i = self.backend.identity()
        for j in challenge.indices:
            b_hat_i = b_hat_i * (file_proof.auth.tags[j] ** challenge.coefficients[j])

        # line 4-6: if b̂i ≠ bi → reject
        return b_hat_i.exponent == file_proof.b.exponent

    def verify(self, stored_batch: StoredBatch, challenge: Challenge, proof: AuditProof) -> bool:
        """
        Algorithm 5 Verify.

        Returns True (accept) or False (reject).
        Requires only 4 constant-size pairings regardless of m or c.
        """
        # lines 1-7: Merkle + tag-recombination check for each file
        for i, (root, fp) in enumerate(zip(stored_batch.roots, proof.file_proofs)):
            if not self._verify_auth(i, root, fp, challenge, proof.auth_mode):
                return False

        # line 8: A ← Πi (bi · Ri · g^(−ỹi))
        A = self.backend.identity()
        for fp in proof.file_proofs:
            term = fp.b * fp.R * (self.g ** (-fp.y_tilde))
            A = A * term

        # line 9: e(A · Cqr, h) ?= e(Cq, h^τ)
        if self.backend.pairing(A * proof.Cqr, 1) != self.backend.pairing(proof.Cq, self.backend.tau):
            return False    # line 10-11: return reject

        # lines 12-14: αi ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, i)
        alphas = [
            self._fiat_shamir_alpha(challenge, stored_batch.roots, proof.file_proofs, proof.Cq, proof.Cqr, i)
            for i in range(self.config.num_files)
        ]

        # line 15: CQ ← Cq · Πi bi^αi
        CQ = proof.Cq
        for alpha_i, fp in zip(alphas, proof.file_proofs):
            CQ = CQ * (fp.b ** alpha_i)

        # line 16: z ← H2(chal, {Γi}, {bi, ỹi, Ri}, Cq, Cqr, CQ)
        z = self._fiat_shamir_z(challenge, stored_batch.roots, proof.file_proofs, proof.Cq, proof.Cqr, CQ)

        # line 17: e(CQ · RQ · g^(−ṼQ) · πbatch^z, h) ?= e(πbatch, h^τ)
        lhs = CQ * proof.RQ * (self.g ** (-proof.V_tilde_Q)) * (proof.pi_batch ** z)
        if self.backend.pairing(lhs, 1) != self.backend.pairing(proof.pi_batch, self.backend.tau):
            return False    # line 18-19: return reject

        return True    # line 20: return accept

    # ------------------------------------------------------------------
    # Testing helpers
    # ------------------------------------------------------------------

    def clone_stored_batch(self, stored_batch: StoredBatch) -> StoredBatch:
        cloned: list[StoredFile] = []
        for sf in stored_batch.files:
            cloned.append(
                StoredFile(
                    sectors=[list(chunk) for chunk in sf.sectors],
                    polynomials=[Polynomial(list(p.coeffs), self.field) for p in sf.polynomials],
                    tags=list(sf.tags),
                    merkle_tree=sf.merkle_tree,
                )
            )
        return StoredBatch(files=cloned, roots=list(stored_batch.roots))

    def tamper_challenged_sector(self, stored_batch: StoredBatch, challenge: Challenge) -> None:
        """Corrupt one sector of the first challenged chunk in file 0 (for tamper-detection tests)."""
        j = challenge.indices[0]
        sf = stored_batch.files[0]
        sf.sectors[j][0] = self.field.add(sf.sectors[j][0], 1)
        sf.polynomials[j] = self._chunk_polynomial(sf.sectors[j])

    def measure_round(self, stored_batch: StoredBatch, challenge: Challenge, auth_mode: AuthMode) -> dict[str, object]:
        before = self.counter.snapshot()
        t0 = time.perf_counter()
        proof = self.proofgen(stored_batch, challenge, auth_mode=auth_mode)
        proofgen_ms = (time.perf_counter() - t0) * 1000
        middle = self.counter.snapshot()
        t1 = time.perf_counter()
        accepted = self.verify(stored_batch, challenge, proof)
        verify_ms = (time.perf_counter() - t1) * 1000
        after = self.counter.snapshot()
        if not accepted:
            raise AssertionError("honest proof should verify")
        return {
            "proof": proof,
            "timing_ms": {"proofgen": round(proofgen_ms, 3), "verify": round(verify_ms, 3)},
            "ops": {
                "proofgen": OperationCounter.diff(middle, before),
                "verify": OperationCounter.diff(after, middle),
            },
        }

    def size_report(self, challenge: Challenge, proof: AuditProof) -> dict[str, int]:
        """
        Communication size breakdown matching Table II of the paper.
        Proof size: m·((c+2)|G1| + |p| + ν_MP(c,n)·|h|) + 4|G1| + 2|p|
        """
        index_bytes = max(1, math.ceil(math.log2(self.config.chunks_per_file) / 8))
        challenge_bytes = (
            len(challenge.indices) * index_bytes
            + len(challenge.indices) * self.config.field_bytes
            + self.config.num_files * self.config.field_bytes
        )
        store_bytes = (
            self.config.num_files * self.config.chunks_per_file * self.config.sectors_per_chunk * self.config.field_bytes
            + self.config.num_files * self.config.chunks_per_file * self.config.group_bytes
            + self.config.num_files * self.config.hash_bytes
        )

        auth_hash_nodes = 0
        for fp in proof.file_proofs:
            if proof.auth_mode == "sp":
                assert fp.auth.single_proofs is not None
                auth_hash_nodes += sum(len(sp.siblings) for sp in fp.auth.single_proofs.values())
            else:
                assert fp.auth.multi_proof is not None
                auth_hash_nodes += fp.auth.multi_proof.node_count

        # Per file: c tags (|G1|), bi (|G1|), Ri (|G1|), ỹi (|p|), Authi (auth_hash_nodes·|h|)
        # Constant: Cq, Cqr, CQ, RQ (4|G1|), ṼQ, z (2|p|  — z is re-derived, not sent)
        proof_bytes = (
            self.config.num_files * len(challenge.indices) * self.config.group_bytes   # c·|G1| per file (tags)
            + self.config.num_files * 2 * self.config.group_bytes                      # bi, Ri per file
            + self.config.num_files * self.config.field_bytes                          # ỹi per file
            + auth_hash_nodes * self.config.hash_bytes                                 # Merkle hashes
            + 4 * self.config.group_bytes                                              # Cq, Cqr, RQ, πbatch
            + 2 * self.config.field_bytes                                              # ṼQ + folded constant
        )
        return {
            "store_bytes": store_bytes,
            "challenge_bytes": challenge_bytes,
            "proof_bytes": proof_bytes,
            "auth_hash_nodes": auth_hash_nodes,
        }

    def config_dict(self) -> dict[str, int]:
        return asdict(self.config)
