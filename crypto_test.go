package zkledger

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
)

func TestNewECPrimeGroupKey(t *testing.T) {
	//	fmt.Println(NewECPrimeGroupKey())
}

func TestECMethods(t *testing.T) {
	v := big.NewInt(3)
	p := EC.G.Mult(v)
	negp := p.Neg()
	sum := EC.Add(p, negp)
	if !sum.Equal(EC.Zero()) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("negp : %v\n", negp)
		fmt.Printf("sum : %v\n", sum)
		t.Fatalf("p + -p should be 0")
	}
	negnegp := negp.Neg()
	if !negnegp.Equal(p) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("negnegp : %v\n", negnegp)
		t.Fatalf("-(-p) should be p")
	}
	sum = EC.Add(p, EC.Zero())
	if !sum.Equal(p) {
		fmt.Printf("p : %v\n", p)
		fmt.Printf("sum : %v\n", sum)
		t.Fatalf("p + 0 should be p")
	}
	fmt.Println("Passed TestECMethods")
}

func TestRToken(t *testing.T) {
	value := big.NewInt(-100)
	pk, sk := EC.KeyGen()

	ecp := ECPedersen{EC.C, EC.G, EC.H}
	comm, r := ecp.Commit(value) // g^v*h^r

	// This breaks it.
	// value = new(big.Int).Mod(value, EC.N)

	X, Y := EC.C.ScalarMult(EC.G.X, EC.G.Y, value.Bytes()) // g^v
	gv1 := ECPoint{X, Y}
	gv := EC.G.Mult(value).Neg() // 1 / g^v
	Dprintf("            g^v: %v value: %v\n", gv1, value)
	Dprintf("          1/g^v: %v\n", gv)

	X, Y = EC.C.Add(gv1.X, gv1.Y, gv.X, gv.Y)
	Dprintf("Added the above: %v %v\n", X, Y)

	T := EC.Add(comm, gv)                             // h^r?
	X, Y = EC.C.ScalarMult(EC.H.X, EC.H.Y, r.Bytes()) // h^r
	HR := ECPoint{X, Y}
	Dprintf("       T: %v\n", T)
	Dprintf("     h^r: %v\n", HR)

	rtoken := EC.CommitR(pk, r) // (h^sk)^r
	proof := ProveEquivalence(T, rtoken, EC.H, pk, sk)
	verify := VerifyEquivalence(T, rtoken, EC.H, pk, proof)
	if !verify {
		Dprintf("        rtoken: %v\n", rtoken)
		Dprintf("         comms: %v\n", comm)
		Dprintf("            gv: %v\n", gv)
		Dprintf("             T: %v\n", T)
		t.Fatalf("Did not verify")
	} else {
		fmt.Println("Passed TestRToken")
	}
}

func TestGSPFS_Verify(t *testing.T) {
	ec := NewECPrimeGroupKey()
	curve, gen1, exp := ec.C, ec.H, ec.N
	gspftInstance := GSPFS{curve, exp, gen1}

	x, err := rand.Int(rand.Reader, gspftInstance.ExponentPrime) // proving knowledge of random value x
	check(err)
	point := gen1.Mult(x)
	proof := gspftInstance.Prove(point, x)

	if gspftInstance.Verify(point, proof) {
		fmt.Println("Passed TestGSPFS_Verify")

	} else {
		t.Error("ZK Proof Error!")
	}
}

func TestVerifyDisjunctive1(t *testing.T) {
	ec := NewECPrimeGroupKey()
	x := big.NewInt(100) // proving knowledge of the value 100

	Base1 := ec.G
	Result1 := ec.G.Mult(x)
	Base2 := ec.G
	Result2 := ec.H

	// we prove of knowledge of x, testing the left hand side
	proof := ProveDisjunctive(Base1, Result1, Base2, Result2, x, 0)
	if VerifyDisjunctive(Base1, Result1, Base2, Result2, proof) {
		fmt.Println("Passed TestVerifyDisjunctive1")
	} else {
		t.Error("Disjunctive proof error!")
	}
}

func TestVerifyDisjunctive2(t *testing.T) {
	ec := NewECPrimeGroupKey()
	x, err := rand.Int(rand.Reader, ec.N) // proving knowledge of a random value
	check(err)

	Base1 := ec.G
	Result1 := ec.H
	Base2 := ec.G
	Result2 := ec.G.Mult(x)

	// we prove of knowledge of x, testing the left hand side
	proof := ProveDisjunctive(Base1, Result1, Base2, Result2, x, 1)
	if VerifyDisjunctive(Base1, Result1, Base2, Result2, proof) {
		fmt.Println("Passed TestVerifyDisjunctive1")
	} else {
		t.Error("Disjunctive proof error!")
	}
}

func TestVerifyEquivalence(t *testing.T) {
	gen1 := EC.H

	x, err := rand.Int(rand.Reader, EC.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, EC.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := EC.C.ScalarMult(gen1.X, gen1.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := EC.C.ScalarMult(gen1.X, gen1.Y, x.Bytes()) // xG
	Result2X, Result2Y := EC.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := gen1
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	eproof := ProveEquivalence(Base1, Result1, Base2, Result2, x)

	if VerifyEquivalence(Base1, Result1, Base2, Result2, eproof) {
		fmt.Println("Passed TestGSPFS_VerifyEquivalence")
	} else {
		t.Error("Equivalence Proof error!")
	}
}

// Tests that our equivalence is correct
func TestVerifyEquivalenceORLog1(t *testing.T) {

	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	// assume we don't know knowledge of y
	Base3 := ec.H
	Result3 := Base2

	p := ProveEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, x, 1) // 1 direction is equivalence
	if p.C == nil {
		t.Error("Verify EquivalenceORLog1 Error")
	}

	if VerifyEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, p) {
		fmt.Println("Passed VerifyEquivalenceORLog1")
	} else {
		t.Error("VerifyEquivlanceORLog1 Error")
	}
}

// Tests that our equivalence is correct
func TestVerifyEquivalenceORLog2(t *testing.T) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	// assume we don't know knowledge of x
	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	// assume knowledge of y
	Base3 := ec.H
	Result3 := Base2

	p := ProveEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, y, 0) // 0 direction is log knowledge
	if p.C == nil {
		t.Error("Verify EquivalenceORLog2 Error")
	}

	if VerifyEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, p) {
		fmt.Println("Passed VerifyEquivalenceORLog2")
	} else {
		t.Error("VerifyEquivlanceORLog2 Error")
	}
}

// Tests that our equivalence is correct
func TestVerifyEquivalenceORLog3(t *testing.T) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	// assume the first two logs are not necessarily equal (one is g^x, other is g^y)
	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ec.H
	Result2 := ECPoint{Base2X, Base2Y}

	// assume knowledge of (g^y)^x
	Base3 := Result2
	Result3 := ECPoint{Result2X, Result2Y}

	p := ProveEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, x, 0) // 0 direction is log knowledge
	if p.C == nil {
		t.Error("Verify EquivalenceORLog3 Error")
	}

	if VerifyEquivalenceORLog(Base1, Result1, Base2, Result2, Base3, Result3, p) {
		fmt.Println("Passed VerifyEquivalenceORLog3")
	} else {
		t.Error("VerifyEquivlanceORLog3 Error")
	}
}

func TestECPedersen_Open(t *testing.T) {
	ec := NewECPrimeGroupKey()
	curve, gen1, gen2 := ec.C, ec.G, ec.H
	ecpedersenInstance := ECPedersen{curve, gen1, gen2}
	value, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), ecpedersenInstance.curve.Params().P)) // 2^32 should be big enough for any value
	check(err)
	comm, r := ecpedersenInstance.Commit(value)
	if ecpedersenInstance.Open(value, r, comm) {
		fmt.Println("Passed ECPedersen_Open")
	} else {
		t.Error("EC Commitment Error!")
	}
}

func TestVerifyConsistency(t *testing.T) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value, err := rand.Int(rand.Reader, ec.N)
	check(err)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	proof := ProveConsistency(cmaux, baux, pk, value, r)

	if !VerifyConsistency(cmaux, baux, pk, proof) {
		t.Error("** Token Consistency Proof failed")
	} else {
		fmt.Println("Passed TestVerifyConsistency")
	}

}

func TestRangeProver_Verify(t *testing.T) {
	ec := NewECPrimeGroupKey()
	ped := ECPedersen{ec.C, ec.G, ec.H}
	value, err := rand.Int(rand.Reader, new(big.Int).SetInt64(1099511627775))
	//	value, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(64), ec.N)) // 2^64 should be big enough for any value
	if err != nil {
		t.Error(err)
	}
	proof, rp := RangeProverProve(value)
	comm := ped.CommitWithR(value, rp)
	if !comm.Equal(proof.ProofAggregate) {
		t.Error("Error computing the randomnesses used -- commitments did not check out when supposed to")
	} else if !RangeProverVerify(comm, proof) {
		t.Error("** Range proof failed")
	} else {
		fmt.Println("Passed TestRangeProver_Verify")
	}
}

func TestOutOfRangeRangeProver_Verify(t *testing.T) {
	ec := NewECPrimeGroupKey()

	min := new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(64), nil)

	value, err := rand.Int(rand.Reader, new(big.Int).Add(new(big.Int).Sub(ec.N, min), min)) // want to make sure it's out of range
	if err != nil {
		t.Error(err)
	}

	proof, rp := RangeProverProve(value)
	if proof != nil || rp != nil {
		t.Error("Error computing the range proof; shouldn't work")
	} else {
		fmt.Println("Passed TestOutOfRangeProver_Verify")
	}
}

func BenchmarkCommitPC(b *testing.B) {
	pc := ECPedersen{EC.C, EC.G, EC.H}
	value := new(big.Int).SetInt64(50)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pc.Commit(value)
	}
}

func BenchmarkOpenPC(b *testing.B) {
	pc := ECPedersen{EC.C, EC.G, EC.H}
	value := new(big.Int).SetInt64(50)

	comm, r := pc.Commit(value)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		pc.Open(value, r, comm)
	}
}

func BenchmarkGSPFS_Prove(b *testing.B) {
	ec := NewECPrimeGroupKey()
	curve, gen1, exp := ec.C, ec.H, ec.N
	gspftInstance := GSPFS{curve, exp, gen1}

	x, err := rand.Int(rand.Reader, new(big.Int).SetInt64(4294967295))
	//x, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), nil)) // proving knowledge of secret key x
	check(err)
	point := ec.H.Mult(x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		gspftInstance.Prove(point, x)
	}
}

func BenchmarkGSPFS_Verify(b *testing.B) {
	ec := NewECPrimeGroupKey()
	curve, gen1, exp := ec.C, ec.H, ec.N
	gspftInstance := GSPFS{curve, exp, gen1}

	x, err := rand.Int(rand.Reader, new(big.Int).SetInt64(4294967295))
	//x, err := rand.Int(rand.Reader, new(big.Int).Exp(new(big.Int).SetInt64(2), new(big.Int).SetInt64(32), nil)) // proving knowledge of secret key x
	check(err)
	point := ec.H.Mult(x)
	proof := gspftInstance.Prove(point, x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		gspftInstance.Verify(point, proof)
	}
}

func BenchmarkZKProofs100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	// we prove of knowledge of x, testing the left hand side

	for n := 0; n < b.N; n++ {
		RangeProverProve(value)
		ProveConsistency(cmaux, baux, pk, value, r)
		ProveEquivalence(Base1, Result1, Base2, Result2, x)
		ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	}
}

func BenchmarkZKVerifies100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	// we prove of knowledge of x, testing the left hand side
	rp, rz := RangeProverProve(value)
	comm := pc.CommitWithR(value, rz)
	cons := ProveConsistency(cmaux, baux, pk, value, r)
	equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
	disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)

	for n := 0; n < b.N; n++ {
		RangeProverVerify(comm, rp)
		VerifyConsistency(cmaux, baux, pk, cons)
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkZKLosdos100(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H

	for n := 0; n < b.N; n++ {
		// we prove
		rp, rz := RangeProverProve(value)
		comm := pc.CommitWithR(value, rz)
		cons := ProveConsistency(cmaux, baux, pk, value, r)
		equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
		disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)

		// we verify
		RangeProverVerify(comm, rp)
		VerifyConsistency(cmaux, baux, pk, cons)
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkProveConsistency(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveConsistency(cmaux, baux, pk, value, r)
	}
}

func BenchmarkVerifyConsistency(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pc := ECPedersen{ec.C, ec.G, ec.H}

	value := big.NewInt(50)

	sk, err2 := rand.Int(rand.Reader, ec.N)
	check(err2)

	pk := ec.H.Mult(sk)

	cmaux, r := pc.Commit(value)
	baux := pk.Mult(r)
	cons := ProveConsistency(cmaux, baux, pk, value, r)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyConsistency(cmaux, baux, pk, cons)
	}

}

func BenchmarkProveEquivalence(b *testing.B) {
	ec := NewECPrimeGroupKey()
	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveEquivalence(Base1, Result1, Base2, Result2, x)
	}

}

func BenchmarkVerifyEquivalence(b *testing.B) {
	ec := NewECPrimeGroupKey()
	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	y, err2 := rand.Int(rand.Reader, ec.N) // multiply our base by another value y
	check(err2)

	Base2X, Base2Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, y.Bytes()) // new = yG

	// now we want to prove knowledge that xG and xyG are the same x for base G and yG

	Result1X, Result1Y := ec.C.ScalarMult(ec.H.X, ec.H.Y, x.Bytes()) // xG
	Result2X, Result2Y := ec.C.ScalarMult(Base2X, Base2Y, x.Bytes())

	Base1 := ec.H
	Result1 := ECPoint{Result1X, Result1Y}

	Base2 := ECPoint{Base2X, Base2Y}
	Result2 := ECPoint{Result2X, Result2Y}

	equiv := ProveEquivalence(Base1, Result1, Base2, Result2, x)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyEquivalence(Base1, Result1, Base2, Result2, equiv)
	}

}

func BenchmarkProveDisjunctive(b *testing.B) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	}
}

func BenchmarkVerifyDisjunctive(b *testing.B) {
	ec := NewECPrimeGroupKey()

	x, err := rand.Int(rand.Reader, ec.N) // our secret X
	check(err)

	Base1z := ec.G
	Result1z := ec.G.Mult(x)
	Base2z := ec.G
	Result2z := ec.H
	disj := ProveDisjunctive(Base1z, Result1z, Base2z, Result2z, x, 0)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		VerifyDisjunctive(Base1z, Result1z, Base2z, Result2z, disj)
	}
}

func BenchmarkRangeProver_Prove(b *testing.B) {
	value := big.NewInt(50)
	for n := 0; n < b.N; n++ {
		RangeProverProve(value)
	}
}

func BenchmarkRangeProver_Verify(b *testing.B) {
	ec := NewECPrimeGroupKey()
	pec := ECPedersen{ec.C, ec.G, ec.H}
	value := big.NewInt(50)
	proof, r := RangeProverProve(value)
	comm := pec.CommitWithR(value, r)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		RangeProverVerify(comm, proof)
	}
}
