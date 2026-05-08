package foldaudit

import "foldaudit/schemes/benchcore"

func challengeBytes(chal *Challenge) []byte {
	parts := make([][]byte, 0, 3+len(chal.Indices)+len(chal.EvaluationPoints))
	parts = append(parts, []byte("challenge"))
	for _, index := range chal.Indices {
		parts = append(parts, benchcore.IntBytes(index))
	}
	for i := range chal.Coefficients {
		parts = append(parts, benchcore.IntBytes(i))
		for _, coefficient := range chal.Coefficients[i] {
			parts = append(parts, benchcore.ScalarBytes(coefficient))
		}
	}
	for _, point := range chal.EvaluationPoints {
		parts = append(parts, benchcore.ScalarBytes(point))
	}
	parts = append(parts, chal.Nonce)
	return benchcore.HashBytes("foldaudit:challenge", parts...)
}

func rootsBytes(roots [][]byte) []byte {
	parts := make([][]byte, 0, len(roots))
	for _, root := range roots {
		parts = append(parts, root)
	}
	return benchcore.HashBytes("foldaudit:roots", parts...)
}

func fileProofStatementBytes(fps []FileProof) []byte {
	parts := make([][]byte, 0, 1+4*len(fps))
	parts = append(parts, []byte("file-proofs"))
	for _, fp := range fps {
		parts = append(parts, benchcore.ScalarBytes(fp.YTilde), g1Bytes(fp.R), g1Bytes(fp.Cw), g1Bytes(fp.B))
	}
	return benchcore.HashBytes("foldaudit:file-proofs", parts...)
}

func maskStatementBytes(roots [][]byte, chal *Challenge, fps []FileProof) []byte {
	// The Schnorr challenge binds the mask proof to the audit statement, so a
	// proof for one challenge/root set cannot be replayed in another audit.
	return benchcore.HashBytes("foldaudit:mask-stmt", challengeBytes(chal), rootsBytes(roots), fileProofStatementBytes(fps))
}

func schnorrProofBytes(proofs []SchnorrProof) []byte {
	// The folding scalar rho is derived after mask proofs are fixed.
	parts := make([][]byte, 0, 1+2*len(proofs))
	parts = append(parts, []byte("schnorr"))
	for _, proof := range proofs {
		parts = append(parts, g1Bytes(proof.A), benchcore.ScalarBytes(proof.Z))
	}
	return benchcore.HashBytes("foldaudit:schnorr", parts...)
}
