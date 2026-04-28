package relatedbench

import (
	"math/big"
	"testing"

	"foldaudit/schemes/benchcore"
	"foldaudit/schemes/miaoscis2026"
	"foldaudit/schemes/xutifs26"
	"foldaudit/schemes/yutc25"
	"foldaudit/schemes/zhangtpds23"
)

func TestXuTIFS26ProtocolRound(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := xutifs26.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "xu"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.TagVerify(stored) {
		t.Fatal("XuTIFS26 tag verification rejected honest storage")
	}
	chal := p.ChallengeFromSeed([]byte("xu-system-test"), c)
	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest XuTIFS26 proof rejected")
	}
	proof.Files[0].Value = benchcore.Add(proof.Files[0].Value, benchcore.One())
	if p.Verify(stored, chal, proof) {
		t.Fatal("tampered XuTIFS26 proof accepted")
	}
}

func TestYuTC25ProtocolRound(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := yutc25.NewProtocol(n, s)
	stored, err := p.StoreBatch(dataset(m, n, s, "yu"))
	if err != nil {
		t.Fatal(err)
	}
	chal := p.BatchChallenge(m, c)
	proof, err := p.ProveBatch(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.VerifyBatch(stored, chal, proof) {
		t.Fatal("honest YuTC25 batch proof rejected")
	}
	proof.Proofs[0].Value = benchcore.Add(proof.Proofs[0].Value, benchcore.One())
	if p.VerifyBatch(stored, chal, proof) {
		t.Fatal("tampered YuTC25 batch proof accepted")
	}
}

func TestZhangTPDS23ProtocolRound(t *testing.T) {
	m, n, s, c := 3, 8, 4, 3
	p := zhangtpds23.NewProtocol(m, n, s)
	stored, err := p.Store(dataset(m, n, s, "zhang"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.TagVerify(stored) {
		t.Fatal("ZhangTPDS23 tag verification rejected honest storage")
	}
	chal := p.ChallengeFromSeed([]byte("zhang-system-test"), c)
	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest ZhangTPDS23 proof rejected")
	}
	proof.E = benchcore.Add(proof.E, benchcore.One())
	if p.Verify(stored, chal, proof) {
		t.Fatal("tampered ZhangTPDS23 proof accepted")
	}
}

func TestMiaoSCIS2026ProtocolRound(t *testing.T) {
	n, c := 8, 3
	p := miaoscis2026.NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: scalars(n, "miao/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: scalars(n, "miao/f1")},
		{FID: "f2", Keywords: []string{"cloud"}, Blocks: scalars(n, "miao/f2")},
	}
	stored, err := p.Store(files)
	if err != nil {
		t.Fatal(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		t.Fatal(err)
	}
	chal := p.ChallengeWithTrapdoor(trap, c, len(files))
	proof, err := p.Prove(stored, chal)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Verify(stored, chal, proof) {
		t.Fatal("honest MiaoSCIS2026 proof rejected")
	}
	proof.Mu1 = benchcore.Add(proof.Mu1, benchcore.One())
	if p.Verify(stored, chal, proof) {
		t.Fatal("tampered MiaoSCIS2026 proof accepted")
	}
}

func BenchmarkConcreteProtocolRounds(b *testing.B) {
	m, n, s, c := 3, 16, 4, 4
	data := dataset(m, n, s, "bench")

	b.Run("XuTIFS26/Prove", func(b *testing.B) {
		p := xutifs26.NewProtocol(m, n, s)
		stored, _ := p.Store(data)
		chal := p.ChallengeFromSeed([]byte("bench/xu"), c)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.Prove(stored, chal); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("XuTIFS26/Verify", func(b *testing.B) {
		p := xutifs26.NewProtocol(m, n, s)
		stored, _ := p.Store(data)
		chal := p.ChallengeFromSeed([]byte("bench/xu"), c)
		proof, _ := p.Prove(stored, chal)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !p.Verify(stored, chal, proof) {
				b.Fatal("verify failed")
			}
		}
	})

	b.Run("YuTC25/Prove", func(b *testing.B) {
		p := yutc25.NewProtocol(n, s)
		stored, _ := p.Store(fileBlocks(n, s, "bench/yu"))
		chal := p.BatchChallenge(1, c).FileChallenges[0]
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.Prove(stored, chal); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("YuTC25/Verify", func(b *testing.B) {
		p := yutc25.NewProtocol(n, s)
		stored, _ := p.Store(fileBlocks(n, s, "bench/yu"))
		chal := p.BatchChallenge(1, c).FileChallenges[0]
		proof, _ := p.Prove(stored, chal)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !p.Verify(stored.Root, chal, proof) {
				b.Fatal("verify failed")
			}
		}
	})

	b.Run("ZhangTPDS23/Prove", func(b *testing.B) {
		p := zhangtpds23.NewProtocol(m, n, s)
		stored, _ := p.Store(data)
		chal := p.ChallengeFromSeed([]byte("bench/zhang"), c)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.Prove(stored, chal); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("ZhangTPDS23/Verify", func(b *testing.B) {
		p := zhangtpds23.NewProtocol(m, n, s)
		stored, _ := p.Store(data)
		chal := p.ChallengeFromSeed([]byte("bench/zhang"), c)
		proof, _ := p.Prove(stored, chal)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !p.Verify(stored, chal, proof) {
				b.Fatal("verify failed")
			}
		}
	})

	b.Run("MiaoSCIS2026/Prove", func(b *testing.B) {
		p, stored, chal := miaoBenchInstance(n, c)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := p.Prove(stored, chal); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("MiaoSCIS2026/Verify", func(b *testing.B) {
		p, stored, chal := miaoBenchInstance(n, c)
		proof, _ := p.Prove(stored, chal)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if !p.Verify(stored, chal, proof) {
				b.Fatal("verify failed")
			}
		}
	})
}

func dataset(m, n, s int, label string) [][][]*big.Int {
	out := make([][][]*big.Int, m)
	for i := 0; i < m; i++ {
		out[i] = fileBlocks(n, s, label+"/file"+string(rune('0'+i)))
	}
	return out
}

func fileBlocks(n, s int, label string) [][]*big.Int {
	out := make([][]*big.Int, n)
	for i := 0; i < n; i++ {
		out[i] = make([]*big.Int, s)
		for j := 0; j < s; j++ {
			out[i][j] = benchcore.Scalar(label, i*s+j)
		}
	}
	return out
}

func scalars(n int, label string) []*big.Int {
	out := make([]*big.Int, n)
	for i := range out {
		out[i] = benchcore.Scalar(label, i)
	}
	return out
}

func miaoBenchInstance(n, c int) (*miaoscis2026.Protocol, *miaoscis2026.StoredData, miaoscis2026.Challenge) {
	p := miaoscis2026.NewProtocol(n)
	files := []struct {
		FID      string
		Keywords []string
		Blocks   []*big.Int
	}{
		{FID: "f0", Keywords: []string{"audit", "cloud"}, Blocks: scalars(n, "bench/miao/f0")},
		{FID: "f1", Keywords: []string{"audit", "chain"}, Blocks: scalars(n, "bench/miao/f1")},
		{FID: "f2", Keywords: []string{"cloud"}, Blocks: scalars(n, "bench/miao/f2")},
	}
	stored, err := p.Store(files)
	if err != nil {
		panic(err)
	}
	trap, err := p.Trapdoor(stored, []string{"audit"})
	if err != nil {
		panic(err)
	}
	return p, stored, p.ChallengeWithTrapdoor(trap, c, len(files))
}
