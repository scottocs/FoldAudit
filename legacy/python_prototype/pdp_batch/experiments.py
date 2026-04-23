from __future__ import annotations

import csv
import json
from pathlib import Path
from statistics import mean

from .protocol import BatchPDPProtocol, ProtocolConfig


def _ensure_results_dir(results_dir: Path | None = None) -> Path:
    target = results_dir or Path("results")
    target.mkdir(parents=True, exist_ok=True)
    return target


def run_correctness_demo(results_dir: Path | None = None) -> dict[str, object]:
    results_dir = _ensure_results_dir(results_dir)
    protocol = BatchPDPProtocol(ProtocolConfig())
    dataset = protocol.random_file_batch()
    stored_batch = protocol.store(dataset)
    challenge = protocol.challenge()
    honest_proof = protocol.proofgen(stored_batch, challenge, auth_mode="mp")
    honest_accept = protocol.verify(stored_batch, challenge, honest_proof)

    tampered_batch = protocol.clone_stored_batch(stored_batch)
    protocol.tamper_challenged_sector(tampered_batch, challenge)
    tampered_proof = protocol.proofgen(tampered_batch, challenge, auth_mode="mp")
    tampered_accept = protocol.verify(tampered_batch, challenge, tampered_proof)

    result = {
        "config": protocol.config_dict(),
        "challenge_indices": challenge.indices,
        "honest_accept": honest_accept,
        "tampered_accept": tampered_accept,
    }
    (results_dir / "correctness_demo.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _sweep_configs(quick: bool) -> list[ProtocolConfig]:
    if quick:
        return [
            ProtocolConfig(num_files=2, chunks_per_file=32, sectors_per_chunk=8, challenged_chunks=4, rng_seed=11),
            ProtocolConfig(num_files=4, chunks_per_file=64, sectors_per_chunk=8, challenged_chunks=8, rng_seed=13),
            ProtocolConfig(num_files=8, chunks_per_file=64, sectors_per_chunk=8, challenged_chunks=8, rng_seed=17),
        ]
    return [
        ProtocolConfig(num_files=2, chunks_per_file=64, sectors_per_chunk=8, challenged_chunks=4, rng_seed=11),
        ProtocolConfig(num_files=4, chunks_per_file=64, sectors_per_chunk=8, challenged_chunks=8, rng_seed=13),
        ProtocolConfig(num_files=8, chunks_per_file=128, sectors_per_chunk=8, challenged_chunks=8, rng_seed=17),
        ProtocolConfig(num_files=16, chunks_per_file=128, sectors_per_chunk=8, challenged_chunks=16, rng_seed=19),
    ]


def run_benchmark_suite(quick: bool = False, repeats: int = 3, results_dir: Path | None = None) -> dict[str, object]:
    results_dir = _ensure_results_dir(results_dir)
    rows: list[dict[str, object]] = []

    for config in _sweep_configs(quick):
        for auth_mode in ("sp", "mp"):
            proofgen_times = []
            verify_times = []
            proofgen_hashes = []
            verify_hashes = []
            proof_sizes = []
            auth_hash_nodes = []
            store_hashes = []
            for repeat in range(repeats):
                run_config = ProtocolConfig(**config.__dict__)
                run_config.rng_seed += repeat
                protocol = BatchPDPProtocol(run_config)
                dataset = protocol.random_file_batch()
                store_before = protocol.counter.snapshot()
                stored_batch = protocol.store(dataset)
                store_after = protocol.counter.snapshot()
                challenge = protocol.challenge()
                round_result = protocol.measure_round(stored_batch, challenge, auth_mode=auth_mode)
                proof = round_result["proof"]
                size_report = protocol.size_report(challenge, proof)
                proofgen_times.append(round_result["timing_ms"]["proofgen"])
                verify_times.append(round_result["timing_ms"]["verify"])
                proofgen_hashes.append(round_result["ops"]["proofgen"]["hashes"])
                verify_hashes.append(round_result["ops"]["verify"]["hashes"])
                proof_sizes.append(size_report["proof_bytes"])
                auth_hash_nodes.append(size_report["auth_hash_nodes"])
                store_hashes.append(store_after["hashes"] - store_before["hashes"])

            rows.append(
                {
                    "auth_mode": auth_mode,
                    "num_files": config.num_files,
                    "chunks_per_file": config.chunks_per_file,
                    "sectors_per_chunk": config.sectors_per_chunk,
                    "challenged_chunks": config.challenged_chunks,
                    "avg_proofgen_ms": round(mean(proofgen_times), 3),
                    "avg_verify_ms": round(mean(verify_times), 3),
                    "avg_proofgen_hashes": round(mean(proofgen_hashes), 3),
                    "avg_verify_hashes": round(mean(verify_hashes), 3),
                    "avg_proof_bytes": round(mean(proof_sizes), 3),
                    "avg_auth_hash_nodes": round(mean(auth_hash_nodes), 3),
                    "avg_store_hashes": round(mean(store_hashes), 3),
                }
            )

    csv_path = results_dir / "benchmark_results.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = {"quick": quick, "repeats": repeats, "rows": rows, "csv": str(csv_path)}
    (results_dir / "benchmark_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary
