// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract KZGPointEvaluationWrapper {
    error PointEvaluationFailed();

    address internal constant POINT_EVALUATION_PRECOMPILE = address(0x0A);

    function verify(
        bytes32 versionedHash,
        bytes32 z,
        bytes32 y,
        bytes calldata commitment,
        bytes calldata proof
    )
        external
        view
        returns (bool ok, uint256 fieldElementsPerBlob, uint256 blsModulus)
    {
        if (commitment.length != 48 || proof.length != 48) {
            revert PointEvaluationFailed();
        }
        bytes memory input = abi.encodePacked(versionedHash, z, y, commitment, proof);
        (bool success, bytes memory output) = POINT_EVALUATION_PRECOMPILE.staticcall(input);
        if (!success || output.length != 64) {
            revert PointEvaluationFailed();
        }

        assembly {
            fieldElementsPerBlob := mload(add(output, 32))
            blsModulus := mload(add(output, 64))
        }
        ok = true;
    }
}
