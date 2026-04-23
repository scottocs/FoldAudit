from __future__ import annotations

import unittest

from pdp_batch.protocol import BatchPDPProtocol, ProtocolConfig


class BatchPDPProtocolTests(unittest.TestCase):
    def test_honest_round_accepts_for_single_and_multi_proofs(self) -> None:
        protocol = BatchPDPProtocol(
            ProtocolConfig(num_files=3, chunks_per_file=16, sectors_per_chunk=4, challenged_chunks=4, rng_seed=21)
        )
        dataset = protocol.random_file_batch()
        stored_batch = protocol.store(dataset)
        challenge = protocol.challenge()

        for auth_mode in ("sp", "mp"):
            proof = protocol.proofgen(stored_batch, challenge, auth_mode=auth_mode)
            self.assertTrue(protocol.verify(stored_batch, challenge, proof))

    def test_tampered_challenged_data_is_detected(self) -> None:
        protocol = BatchPDPProtocol(
            ProtocolConfig(num_files=2, chunks_per_file=16, sectors_per_chunk=4, challenged_chunks=4, rng_seed=22)
        )
        dataset = protocol.random_file_batch()
        stored_batch = protocol.store(dataset)
        challenge = protocol.challenge()

        tampered_batch = protocol.clone_stored_batch(stored_batch)
        protocol.tamper_challenged_sector(tampered_batch, challenge)
        tampered_proof = protocol.proofgen(tampered_batch, challenge, auth_mode="mp")
        self.assertFalse(protocol.verify(tampered_batch, challenge, tampered_proof))

    def test_multi_proof_uses_fewer_or_equal_hash_nodes_than_single_paths(self) -> None:
        protocol = BatchPDPProtocol(
            ProtocolConfig(num_files=2, chunks_per_file=32, sectors_per_chunk=4, challenged_chunks=8, rng_seed=23)
        )
        dataset = protocol.random_file_batch()
        stored_batch = protocol.store(dataset)
        challenge = protocol.challenge()

        proof_sp = protocol.proofgen(stored_batch, challenge, auth_mode="sp")
        proof_mp = protocol.proofgen(stored_batch, challenge, auth_mode="mp")
        sizes_sp = protocol.size_report(challenge, proof_sp)
        sizes_mp = protocol.size_report(challenge, proof_mp)
        self.assertLessEqual(sizes_mp["auth_hash_nodes"], sizes_sp["auth_hash_nodes"])


if __name__ == "__main__":
    unittest.main()
