package foldaudit

func challengeBytes(chal *Challenge) []byte {
	parts := make([][]byte, 0, 3+len(chal.Indices)+len(chal.EvaluationPoints))
	parts = append(parts, []byte("challenge"))
	for _, index := range chal.Indices {
		parts = append(parts, intBytes(index))
	}
	for i := range chal.Coefficients {
		parts = append(parts, intBytes(i))
		for _, coefficient := range chal.Coefficients[i] {
			parts = append(parts, scalarBytes(coefficient))
		}
	}
	for _, point := range chal.EvaluationPoints {
		parts = append(parts, scalarBytes(point))
	}
	parts = append(parts, chal.Nonce)
	return hashBytes("foldaudit:challenge", parts...)
}

func rootsBytes(roots [][]byte) []byte {
	parts := make([][]byte, 0, len(roots))
	for _, root := range roots {
		parts = append(parts, root)
	}
	return hashBytes("foldaudit:roots", parts...)
}

func fileProofStatementBytes(fps []FileProof) []byte {
	parts := make([][]byte, 0, 1+4*len(fps))
	parts = append(parts, []byte("file-proofs"))
	for _, fp := range fps {
		parts = append(parts, scalarBytes(fp.YTilde), g1Bytes(fp.R), g1Bytes(fp.Cw), g1Bytes(fp.B))
	}
	return hashBytes("foldaudit:file-proofs", parts...)
}

func maskStatementBytes(roots [][]byte, chal *Challenge, fps []FileProof) []byte {
	return hashBytes("foldaudit:mask-stmt", challengeBytes(chal), rootsBytes(roots), fileProofStatementBytes(fps))
}

func schnorrProofBytes(proofs []SchnorrProof) []byte {
	parts := make([][]byte, 0, 1+2*len(proofs))
	parts = append(parts, []byte("schnorr"))
	for _, proof := range proofs {
		parts = append(parts, g1Bytes(proof.A), scalarBytes(proof.Z))
	}
	return hashBytes("foldaudit:schnorr", parts...)
}
