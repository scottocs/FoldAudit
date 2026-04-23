from __future__ import annotations

import json
from pathlib import Path

from solcx import compile_standard, install_solc


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "KZGPointEvaluationWrapper.sol"
ARTIFACT = ROOT / "KZGPointEvaluationWrapper.json"
SOLC_VERSION = "0.8.24"


def main() -> None:
    install_solc(SOLC_VERSION)
    source = SOURCE.read_text(encoding="utf-8")
    compiled = compile_standard(
        {
            "language": "Solidity",
            "sources": {SOURCE.name: {"content": source}},
            "settings": {
                "optimizer": {"enabled": True, "runs": 200},
                "outputSelection": {
                    "*": {
                        "*": [
                            "abi",
                            "evm.bytecode.object",
                            "evm.deployedBytecode.object",
                        ]
                    }
                },
            },
        },
        solc_version=SOLC_VERSION,
    )

    contract = compiled["contracts"][SOURCE.name]["KZGPointEvaluationWrapper"]
    artifact = {
        "contractName": "KZGPointEvaluationWrapper",
        "abi": contract["abi"],
        "bytecode": contract["evm"]["bytecode"]["object"],
        "deployedBytecode": contract["evm"]["deployedBytecode"]["object"],
        "solcVersion": SOLC_VERSION,
    }
    ARTIFACT.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    print(f"wrote {ARTIFACT}")


if __name__ == "__main__":
    main()
