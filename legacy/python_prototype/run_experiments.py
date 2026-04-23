from __future__ import annotations

import argparse
import json

from pdp_batch import run_benchmark_suite, run_correctness_demo


def main() -> None:
    parser = argparse.ArgumentParser(description="Run PDP batch-verification experiments.")
    parser.add_argument("--quick", action="store_true", help="Run a smaller benchmark sweep.")
    parser.add_argument("--repeats", type=int, default=3, help="Benchmark repeats per configuration.")
    args = parser.parse_args()

    correctness = run_correctness_demo()
    benchmarks = run_benchmark_suite(quick=args.quick, repeats=args.repeats)
    print(json.dumps({"correctness": correctness, "benchmarks": benchmarks}, indent=2))


if __name__ == "__main__":
    main()
