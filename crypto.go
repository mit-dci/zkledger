package zkledger

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"math/big"
	"sync"

	"github.com/narula/btcd/btcec"
)

const (
	DEFAULT_RSA_KEY_SIZE = 4096
)

var baseMult = flag.Bool("baseMult", true, "Use ScalarBaseMult when multiplying G and H")

var EC APLCrypto

// H2tothe is a slice populated with H, 2H, 4H, 8H... .. 2^64H
var H2tothe []ECPoint

func check(e error) {
	if e != nil {
		panic(e)
	}
}

type ECPoint struct {
	X, Y *big.Int
}

// Equal returns true if points p (self) and p2 (arg) are the same.
func (p ECPoint) Equal(p2 ECPoint) bool {
	if p.X.Cmp(p2.X) == 0 && p2.Y.Cmp(p2.Y) == 0 {
		return true
	}
	return false
}

// Mult multiplies point p by scalar s and returns the resulting point
func (p ECPoint) Mult(s *big.Int) ECPoint {
	modS := new(big.Int).Mod(s, EC.N)
	X, Y := EC.C.ScalarMult(p.X, p.Y, modS.Bytes())
	return ECPoint{X, Y}
}

// Add adds points p and p2 and returns the resulting point
func (p ECPoint) Add(p2 ECPoint) ECPoint {
	X, Y := EC.C.Add(p.X, p.Y, p2.X, p2.Y)
	return ECPoint{X, Y}
}

// Neg returns the addadtive inverse of point p
func (p ECPoint) Neg() ECPoint {
	negY := new(big.Int).Neg(p.Y)
	modValue := negY.Mod(negY, EC.C.Params().P)
	return ECPoint{p.X, modValue}
}

type APLCrypto struct {
	C  elliptic.Curve      // curve
	KC *btcec.KoblitzCurve // curve
	G  ECPoint             // generator 1
	H  ECPoint             // generator 2
	N  *big.Int            // exponent prime
}

func (e APLCrypto) Add(a ECPoint, b ECPoint) ECPoint {
	cx, cy := e.C.Add(a.X, a.Y, b.X, b.Y)
	return ECPoint{cx, cy}
}

func (e APLCrypto) CommitR(pk ECPoint, r *big.Int) ECPoint {
	newR := new(big.Int).Mod(r, e.N)
	X, Y := e.C.ScalarMult(pk.X, pk.Y, newR.Bytes())
	return ECPoint{X, Y}
}

func (e APLCrypto) VerifyR(rt ECPoint, pk ECPoint, r *big.Int) bool {
	p := e.CommitR(pk, r)
	if p.Equal(rt) {
		return true
	}
	return false
}

func (e APLCrypto) Zero() ECPoint {
	return ECPoint{big.NewInt(0), big.NewInt(0)}
}

///////////////////////
// PEDERSEN COMMITMENTS

type ECPedersen struct {
	curve elliptic.Curve
	G     ECPoint
	H     ECPoint
}

func (ep *ECPedersen) Commit(value *big.Int) (ECPoint, *big.Int) {

	modValue := new(big.Int).Mod(value, ep.curve.Params().N)

	r, err := rand.Int(rand.Reader, ep.curve.Params().N)
	check(err)

	// mG, rH
	lhsX, lhsY := ep.curve.ScalarMult(ep.G.X, ep.G.Y, modValue.Bytes())
	rhsX, rhsY := ep.curve.ScalarMult(ep.H.X, ep.H.Y, r.Bytes())

	//mG + rH
	commX, commY := ep.curve.Add(lhsX, lhsY, rhsX, rhsY)

	return ECPoint{commX, commY}, r
}

func (ep *ECPedersen) CommitWithR(value *big.Int, r *big.Int) ECPoint {

	modValue := new(big.Int).Mod(value, ep.curve.Params().N)

	// mG, rH
	var lhsX, lhsY, rhsX, rhsY *big.Int
	if *baseMult {
		lhsX, lhsY = EC.C.ScalarBaseMult(modValue.Bytes())
		rhsX, rhsY = EC.KC.ScalarBaseMultH(r.Bytes())
	} else {
		lhsX, lhsY = ep.curve.ScalarMult(ep.G.X, ep.G.Y, modValue.Bytes())
		rhsX, rhsY = ep.curve.ScalarMult(ep.H.X, ep.H.Y, r.Bytes())
	}

	//mG + rH
	commX, commY := ep.curve.Add(lhsX, lhsY, rhsX, rhsY)

	return ECPoint{commX, commY}
}

func (ep *ECPedersen) Compute(value *big.Int, r *big.Int) ECPoint {
	modValue := new(big.Int).Mod(value, ep.curve.Params().N)
	// mG, rH
	lhsX, lhsY := ep.curve.ScalarMult(ep.G.X, ep.G.Y, modValue.Bytes())
	rhsX, rhsY := ep.curve.ScalarMult(ep.H.X, ep.H.Y, r.Bytes())
	tempCommX, tempCommY := ep.curve.Add(lhsX, lhsY, rhsX, rhsY)
	return ECPoint{tempCommX, tempCommY}
}

func (ep *ECPedersen) Open(value *big.Int, r *big.Int, comm ECPoint) bool {
	modValue := new(big.Int).Mod(value, ep.curve.Params().N)

	// mG, rH
	lhsX, lhsY := ep.curve.ScalarMult(ep.G.X, ep.G.Y, modValue.Bytes())
	rhsX, rhsY := ep.curve.ScalarMult(ep.H.X, ep.H.Y, r.Bytes())

	//mG + rH
	tempCommX, tempCommY := ep.curve.Add(lhsX, lhsY, rhsX, rhsY)
	if tempCommX.Cmp(comm.X) == 0 && tempCommY.Cmp(comm.Y) == 0 {
		return true
	}
	return false
}

///////////////////////
// GENERALIZED SCHNORR PROOFS

// Generalized Schnorr Proofs with Fiat-Shamir transform
type GSPFS struct {
	curve         elliptic.Curve `json:"prime"`         // p
	ExponentPrime *big.Int       `json:"ExponentPrime"` // q
	Generator     ECPoint        `json:"Generator"`     // g
}

type GSPFSProof struct {
	T ECPoint  `json:"T"`
	R *big.Int `json:"R"`
	C *big.Int `json:"C"`
}

// we want to prove the knowledge of the secret key x
func (g *GSPFS) Prove(result1 ECPoint, x *big.Int) *GSPFSProof {
	// v \in Z_q
	v, err := rand.Int(rand.Reader, EC.N)
	// tG is the randomness
	tX, tY := g.curve.ScalarMult(g.Generator.X, g.Generator.Y, v.Bytes())

	check(err)
	// generate string to hash
	s := g.Generator.X.String() + "," + g.Generator.Y.String() + "," +
		result1.X.String() + "," + result1.Y.String() + "," +
		tX.String() + "," + tY.String()

	shashed := sha256.Sum256([]byte(s))
	c := new(big.Int).SetBytes(shashed[:])

	r := new(big.Int).Sub(v, new(big.Int).Mul(c, x))
	r.Mod(r, EC.N)
	return &GSPFSProof{ECPoint{tX, tY}, r, c}
}

func (g *GSPFS) Verify(result1 ECPoint, proof *GSPFSProof) bool {
	// generate C
	s256 := sha256.New()
	s := g.Generator.X.String() + "," + g.Generator.Y.String() + "," +
		result1.X.String() + "," + result1.Y.String() + "," +
		proof.T.X.String() + "," + proof.T.Y.String()

	s256.Write([]byte(s))
	c := new(big.Int).SetBytes(s256.Sum(nil))

	if c.Cmp(proof.C) != 0 {
		return false
	}

	// rG
	grX, grY := EC.C.ScalarMult(g.Generator.X, g.Generator.Y, proof.R.Bytes())
	// cY
	rhsX, rhsY := EC.C.ScalarMult(result1.X, result1.Y, c.Bytes())
	// rG + cY
	totX, totY := EC.C.Add(grX, grY, rhsX, rhsY)

	if proof.T.X.Cmp(totX) != 0 || proof.T.Y.Cmp(totY) != 0 {
		return false
	}
	return true
}

type EquivProof struct {
	B1K ECPoint  `json:"B1K"`
	B2K ECPoint  `json:"B2K"`
	C   *big.Int `json:"C"`
	S   *big.Int `json:"S"`
}

// ProveEquivalence proves that xBase1 = Result1 and xBase2 = Result2 i.e.,
// that the powers used in each case are the same
func ProveEquivalence(
	Base1, Result1, Base2, Result2 ECPoint, x *big.Int) EquivProof {

	// will check that x is in fact the correct secret for each base
	lhs1X, lhs1Y := EC.C.ScalarMult(Base1.X, Base1.Y, x.Bytes())
	if lhs1X.Cmp(Result1.X) != 0 || lhs1Y.Cmp(Result1.Y) != 0 {
		Dprintf("You're lying about base 1 and result 1 -- secrets don't match\n")
	}

	lhs2X, lhs2Y := EC.C.ScalarMult(Base2.X, Base2.Y, x.Bytes())
	if lhs2X.Cmp(Result2.X) != 0 || lhs2Y.Cmp(Result2.Y) != 0 {
		Dprintf("You're lying about base 2 and result 2 -- secrets don't match\n")
	}

	// continue with proof
	k, err := rand.Int(rand.Reader, EC.N)
	check(err)
	// A' = k*Base1
	base1ToKX, base1ToKY := EC.C.ScalarMult(Base1.X, Base1.Y, k.Bytes())
	// C' = k*Base2
	base2ToKX, base2ToKY := EC.C.ScalarMult(Base2.X, Base2.Y, k.Bytes())

	stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
		Base2.X.String() + "||" + Base2.Y.String() + ";" +
		Result1.X.String() + "||" + Result1.Y.String() + ";" +
		Result2.X.String() + "||" + Result2.Y.String() + ";" +
		base1ToKX.String() + "||" + base1ToKY.String() + ";" +
		base2ToKX.String() + "||" + base2ToKY.String() + ";"

	s256 := sha256.New()
	s256.Write([]byte(stringToHash))

	c := new(big.Int).SetBytes(s256.Sum(nil))

	s := new(big.Int).Add(k, new(big.Int).Mul(c, x))
	s.Mod(s, EC.N)
	return EquivProof{
		B1K: ECPoint{base1ToKX, base1ToKY},
		B2K: ECPoint{base2ToKX, base2ToKY},
		C:   c,
		S:   s}
}

func VerifyEquivalence(
	Base1, Result1, Base2, Result2 ECPoint, ep EquivProof) bool {
	//calculate C
	stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
		Base2.X.String() + "||" + Base2.Y.String() + ";" +
		Result1.X.String() + "||" + Result1.Y.String() + ";" +
		Result2.X.String() + "||" + Result2.Y.String() + ";" +
		ep.B1K.X.String() + "||" + ep.B1K.Y.String() + ";" +
		ep.B2K.X.String() + "||" + ep.B2K.Y.String() + ";"

	s256 := sha256.New()
	s256.Write([]byte(stringToHash))

	calculatedC := new(big.Int).SetBytes(s256.Sum(nil))

	if ep.C.Cmp(calculatedC) != 0 {
		Dprintf(" [crypto] c comparison failed. proof: %v calculated: %v\n",
			ep.C, calculatedC)
		return false
	}
	lhsX, lhsY := EC.C.ScalarMult(Base1.X, Base1.Y, ep.S.Bytes())
	rhs1X, rhs1Y := EC.C.ScalarMult(Result1.X, Result1.Y, ep.C.Bytes())
	rhsX, rhsY := EC.C.Add(ep.B1K.X, ep.B1K.Y, rhs1X, rhs1Y)

	if lhsX.Cmp(rhsX) != 0 || lhsY.Cmp(rhsY) != 0 {
		Dprintf(" [crypto] lhs/rhs cmp failed. lhsX %v lhsY %v rhsX %v rhsY %v\n",
			lhsX, lhsY, rhsX, rhsY)
		return false
	}
	lhs2X, lhs2Y := EC.C.ScalarMult(Base2.X, Base2.Y, ep.S.Bytes())
	rhs21X, rhs21Y := EC.C.ScalarMult(Result2.X, Result2.Y, ep.C.Bytes())
	rhs2X, rhs2Y := EC.C.Add(ep.B2K.X, ep.B2K.Y, rhs21X, rhs21Y)

	if lhs2X.Cmp(rhs2X) != 0 || lhs2Y.Cmp(rhs2Y) != 0 {
		Dprintf(
			" [crypto] lhs/rhs2 cmp failed. lhs2X %v lhs2Y %v rhs2X %v rhs2Y %v\n",
			lhs2X, lhs2Y, rhs2X, rhs2Y)
		return false
	}
	return true
}

type DisjunctiveGSPFSProof struct {
	C   *big.Int // verifier challenge: with FS transform, it is the hash of public info
	C1  *big.Int // c1 = c-c2 mod N
	C2  *big.Int // c2 is a random int mod N
	S1  *big.Int // t_1 + c_1 * x_1 (where x_1 is the value we are proving knowledge of)
	S2  *big.Int // random value mod N
	B1U ECPoint  // base1 raised to some randomness
	B2U ECPoint  // base2 raised to some randomness
}

/// ProveDisjunctive
// Proof of knowledge that either log_{Base1} Result1 == x OR log_{Base2} Result2 == x
//
// Base1 - base value
// Result1 - result we want to prove
// Base2 - second base value
// Result2 - result we want to prove
// x - our secret knowledge
// side - 0 proves the left hand side, 1 proves the right hand side
//
// reviewing figure 5 from the following paper:
// http://cgi.di.uoa.gr/~aggelos/crypto/assets/7_zk_handout.pdf
// we will prove the item that we want and then simulate the one we don't want

func ProveDisjunctive(
	Base1 ECPoint, Result1 ECPoint,
	Base2 ECPoint, Result2 ECPoint, x *big.Int, side uint) *DisjunctiveGSPFSProof {

	if side == 0 { // prove the left hand side

		if !Base1.Mult(x).Equal(Result1) {
			Dprintf("Seems like we're lying about values we know...", x, Result1)
		}

		u, err := rand.Int(rand.Reader, EC.N)
		check(err)

		b1uX, b1uY := EC.C.ScalarMult(Base1.X, Base1.Y, u.Bytes())

		s2, err2 := rand.Int(rand.Reader, EC.N)
		check(err2)

		c2, err3 := rand.Int(rand.Reader, EC.N)
		check(err3)

		c2Neg := new(big.Int).Neg(c2)
		c2Neg.Mod(c2Neg, EC.N)

		lhsX, lhsY := EC.C.ScalarMult(Base2.X, Base2.Y, s2.Bytes())
		rhsX, rhsY := EC.C.ScalarMult(Result2.X, Result2.Y, c2Neg.Bytes())

		b2uX, b2uY := EC.C.Add(lhsX, lhsY, rhsX, rhsY)

		s256 := sha256.New()
		// generate string to hash

		s := Base1.X.String() + "," + Base1.Y.String() + ";" +
			Result1.X.String() + "," + Result1.Y.String() + ";" +
			Base2.X.String() + "," + Base2.Y.String() + ";" +
			Result2.X.String() + "," + Result2.Y.String() + ";" +
			b1uX.String() + "," + b1uY.String() + ";" +
			b2uX.String() + "," + b2uY.String() + ";"

		s256.Write([]byte(s))
		c := new(big.Int).SetBytes(s256.Sum(nil))

		c1 := new(big.Int).Sub(c, c2)
		c1.Mod(c1, EC.N)

		s1 := new(big.Int).Add(u, new(big.Int).Mul(c1, x))
		return &DisjunctiveGSPFSProof{c,
			c1,
			c2,
			s1,
			s2,
			ECPoint{b1uX, b1uY},
			ECPoint{b2uX, b2uY}}

	} else if side == 1 { // prove the right hand side
		if !Base2.Mult(x).Equal(Result2) {
			fmt.Println("ughugh")
			panic("")
		}

		u, err := rand.Int(rand.Reader, EC.N)
		check(err)

		b2uX, b2uY := EC.C.ScalarMult(Base2.X, Base2.Y, u.Bytes())

		s1, err1 := rand.Int(rand.Reader, EC.N)
		check(err1)

		c1, err1 := rand.Int(rand.Reader, EC.N)
		check(err1)

		c1Neg := new(big.Int).Neg(c1)
		c1Neg.Mod(c1Neg, EC.N)

		lhsX, lhsY := EC.C.ScalarMult(Base1.X, Base1.Y, s1.Bytes())
		rhsX, rhsY := EC.C.ScalarMult(Result1.X, Result1.Y, c1Neg.Bytes())

		b1uX, b1uY := EC.C.Add(lhsX, lhsY, rhsX, rhsY)

		s256 := sha256.New()
		// generate string to hash

		s := Base1.X.String() + "," + Base1.Y.String() + ";" +
			Result1.X.String() + "," + Result1.Y.String() + ";" +
			Base2.X.String() + "," + Base2.Y.String() + ";" +
			Result2.X.String() + "," + Result2.Y.String() + ";" +
			b1uX.String() + "," + b1uY.String() + ";" +
			b2uX.String() + "," + b2uY.String() + ";"

		s256.Write([]byte(s))
		c := new(big.Int).SetBytes(s256.Sum(nil))

		c2 := new(big.Int).Sub(c, c1)
		c2.Mod(c2, EC.N)

		s2 := new(big.Int).Add(u, new(big.Int).Mul(c2, x))
		return &DisjunctiveGSPFSProof{c,
			c1,
			c2,
			s1,
			s2,
			ECPoint{b1uX, b1uY},
			ECPoint{b2uX, b2uY}}
	}

	Dprintf(" ERROR -- WRONG SIDE GIVEN")
	return nil
}

// VerifyDisjunctive
func VerifyDisjunctive(
	Base1 ECPoint, Result1 ECPoint, Base2 ECPoint, Result2 ECPoint,
	proof *DisjunctiveGSPFSProof) bool {

	C := proof.C
	C1 := proof.C1
	C2 := proof.C2
	S1 := proof.S1
	S2 := proof.S2
	B1U := proof.B1U
	B2U := proof.B2U

	s256 := sha256.New()
	// generate string to hash

	s := Base1.X.String() + "," + Base1.Y.String() + ";" +
		Result1.X.String() + "," + Result1.Y.String() + ";" +
		Base2.X.String() + "," + Base2.Y.String() + ";" +
		Result2.X.String() + "," + Result2.Y.String() + ";" +
		B1U.X.String() + "," + B1U.Y.String() + ";" +
		B2U.X.String() + "," + B2U.Y.String() + ";"

	s256.Write([]byte(s))
	calculatedC := new(big.Int).SetBytes(s256.Sum(nil))

	if calculatedC.Cmp(C) != 0 {
		fmt.Println("uhoh")
		return false
	}

	// make sure that the C values add up and there's no cheating
	cTot := new(big.Int).Add(C1, C2)
	cTot.Mod(cTot, EC.N)
	if cTot.Cmp(C) != 0 {
		fmt.Println("yodawg")
		return false
	}

	// check the H1 side
	h1c1X, h1c1Y := EC.C.ScalarMult(Result1.X, Result1.Y, C1.Bytes())
	rhs1X, rhs1Y := EC.C.Add(h1c1X, h1c1Y, B1U.X, B1U.Y)
	lhs1X, lhs1Y := EC.C.ScalarMult(Base1.X, Base1.Y, S1.Bytes())

	if lhs1X.Cmp(rhs1X) != 0 && lhs1Y.Cmp(rhs1Y) != 0 {
		fmt.Println("fightme")
		return false
	}

	// check the H2 side
	h2c2X, h2c2Y := EC.C.ScalarMult(Result2.X, Result2.Y, C2.Bytes())
	rhs2X, rhs2Y := EC.C.Add(h2c2X, h2c2Y, B2U.X, B2U.Y)
	lhs2X, lhs2Y := EC.C.ScalarMult(Base2.X, Base2.Y, S2.Bytes())

	if lhs2X.Cmp(rhs2X) != 0 && lhs2Y.Cmp(rhs2Y) != 0 {
		fmt.Println("welp")
		return false
	}

	return true
}

/*func VerifyZeroSumCommitments(etx EncryptedTransaction, gsp GSPFS) bool {
	// get the first commitment value
	totalX := big.NewInt(0)
	totalY := big.NewInt(0)

	for _, entry := range etx.Entries {
		totalX, totalY = EC.C.Add(totalX, totalY, entry.Comm.X, entry.Comm.Y)
	}
	return gsp.Verify(ECPoint{totalX, totalY}, etx.ZeroSumProof)
}*/

type EquivORLogProof struct {
	B1u ECPoint  // Either u1 * Base1 or s1*Base1 - c1 * Result1
	B2u ECPoint  // Either u1 * Base2 or s1*Base2 - c1 * Result2
	B3u ECPoint  // Either u2 * Base3 or s2*Base3 - c2 * Result3
	S1  *big.Int // Either s1=u1 + c1x or random element
	S2  *big.Int // Either s2=u2 + c2x or random element
	C1  *big.Int // Challenge 1
	C2  *big.Int // Challenge 2
	C   *big.Int // Sum of challenges
}

//// ProveEquivalenceORLog
// Takes in Base1, Result1, Base2, Result2, Base3, Result3, x, equivalence
//
// Verifies a proof that either knowledge of x s.t.
// 	(1) log_{Base1} Result1 == log_{Base2} Result2 == x OR
// 	(2) log_{Base3} Result3 == x
//  equivalence decides whether we show (1) or (2)
//
// For proof of well-formedness:
//  - Base1 = H
//  - Result1 = A_i
//  - Base2 = PK_i
//  - Result2 = B_i
//  - Base3 = H
//  - Result3 = PK_i
//   If you're showing proof of equivalence, your x value is r_i and set equivalence=1
//   If you're showing proof of knowledge of log, your x value is sk_i and set equivalence=0
//
// For Rerandomization during Auditing:
//  - Base1 = A_i
//  - Result1 = B_i
//  - Base2 = H
//  - Result2 = PK_i
//  - Base3 = H
//  - Result3 = C_i/A_i = ec.Add(C_i.X, C_i.Y, A_i.X, new(big.Int).Neg(A_i.Y))
//   If you're showing proof of equivalence, your x value is sk_i and set equivalence=1
//   If you're showing proof of knowledge of log, your x value is
//   x' = new(big.Int).Sub(r',r) and set equivalence=0
//
// Returns a proof of either direction with the non-chosen one simulated.

func ProveEquivalenceORLog(Base1 ECPoint, Result1 ECPoint, // used for equivalence
	Base2 ECPoint, Result2 ECPoint, // used for equivalence
	Base3 ECPoint, Result3 ECPoint, // used for log-check
	x *big.Int, equivalence uint) EquivORLogProof {

	if equivalence == 1 {
		// we will show knowledge of equivalence of log_{Base1}
		// Result1 and log_{Base2} Result2 and simulate knowledge of
		// log_{Base3} Result3
		c2, err := rand.Int(rand.Reader, EC.N)
		check(err)
		s2, err1 := rand.Int(rand.Reader, EC.N)
		check(err1)
		u1, err2 := rand.Int(rand.Reader, EC.N)
		check(err2)

		c2Neg := new(big.Int).Neg(c2)
		c2Neg.Mod(c2Neg, EC.N)

		Base1ToUX, Base1ToUY := EC.C.ScalarMult(Base1.X, Base1.Y, u1.Bytes())
		Base2ToUX, Base2ToUY := EC.C.ScalarMult(Base2.X, Base2.Y, u1.Bytes())

		rhs1X, rhs1Y := EC.C.ScalarMult(Result3.X, Result3.Y, c2Neg.Bytes())
		rhs2X, rhs2Y := EC.C.ScalarMult(Base3.X, Base3.Y, s2.Bytes())
		Base3SimX, Base3SimY := EC.C.Add(rhs1X, rhs1Y, rhs2X, rhs2Y)

		stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
			Base2.X.String() + "||" + Base2.Y.String() + ";" +
			Base3.X.String() + "||" + Base3.Y.String() + ";" +
			Result1.X.String() + "||" + Result1.Y.String() + ";" +
			Result2.X.String() + "||" + Result2.Y.String() + ";" +
			Result3.X.String() + "||" + Result3.Y.String() + ";" +
			Base1ToUX.String() + "||" + Base1ToUY.String() + ";" +
			Base2ToUX.String() + "||" + Base2ToUY.String() + ";" +
			Base3SimX.String() + "||" + Base3SimY.String() + ";"

		s256 := sha256.New()
		s256.Write([]byte(stringToHash))
		c := new(big.Int).SetBytes(s256.Sum(nil))

		c1 := new(big.Int).Add(c, c2Neg)
		c1.Mod(c1, EC.N)

		s1 := new(big.Int).Add(u1, new(big.Int).Mul(c1, x))
		s1.Mod(s1, EC.N)

		return EquivORLogProof{
			B1u: ECPoint{Base1ToUX, Base1ToUY},
			B2u: ECPoint{Base2ToUX, Base2ToUY},
			B3u: ECPoint{Base3SimX, Base3SimY},
			S1:  s1, S2: s2, C1: c1, C2: c2, C: c,
		}

	} else if equivalence == 0 {

		// we will show knowledge of log_{Base3} Result3 and simulate knowledge
		// of equivalence
		c1, err := rand.Int(rand.Reader, EC.N)
		check(err)
		s1, err1 := rand.Int(rand.Reader, EC.N)
		check(err1)
		u2, err2 := rand.Int(rand.Reader, EC.N)
		check(err2)

		c1Neg := new(big.Int).Neg(c1)
		c1Neg.Mod(c1Neg, EC.N)

		rhsB11X, rhsB11Y := EC.C.ScalarMult(Result1.X, Result1.Y, c1Neg.Bytes())
		rhsB12X, rhsB12Y := EC.C.ScalarMult(Base1.X, Base1.Y, s1.Bytes())
		Base1SimX, Base1SimY := EC.C.Add(rhsB11X, rhsB11Y, rhsB12X, rhsB12Y)

		rhsB21X, rhsB21Y := EC.C.ScalarMult(Result2.X, Result2.Y, c1Neg.Bytes())
		rhsB22X, rhsB22Y := EC.C.ScalarMult(Base2.X, Base2.Y, s1.Bytes())
		Base2SimX, Base2SimY := EC.C.Add(rhsB21X, rhsB21Y, rhsB22X, rhsB22Y)

		Base3ToUX, Base3ToUY := EC.C.ScalarMult(Base3.X, Base3.Y, u2.Bytes())

		stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
			Base2.X.String() + "||" + Base2.Y.String() + ";" +
			Base3.X.String() + "||" + Base3.Y.String() + ";" +
			Result1.X.String() + "||" + Result1.Y.String() + ";" +
			Result2.X.String() + "||" + Result2.Y.String() + ";" +
			Result3.X.String() + "||" + Result3.Y.String() + ";" +
			Base1SimX.String() + "||" + Base1SimY.String() + ";" +
			Base2SimX.String() + "||" + Base2SimY.String() + ";" +
			Base3ToUX.String() + "||" + Base3ToUY.String() + ";"

		s256 := sha256.New()
		s256.Write([]byte(stringToHash))
		c := new(big.Int).SetBytes(s256.Sum(nil))

		c2 := new(big.Int).Add(c, c1Neg)
		c2.Mod(c2, EC.N)

		s2 := new(big.Int).Add(u2, new(big.Int).Mul(c2, x))
		s2.Mod(s2, EC.N)

		return EquivORLogProof{
			B1u: ECPoint{Base1SimX, Base1SimY},
			B2u: ECPoint{Base2SimX, Base2SimY},
			B3u: ECPoint{Base3ToUX, Base3ToUY},
			S1:  s1, S2: s2, C1: c1, C2: c2, C: c,
		}
	}

	fmt.Println("Wrong direction given for ProveEquivalenceORLog")
	return EquivORLogProof{
		B1u: ECPoint{}, B2u: ECPoint{}, B3u: ECPoint{},
		S1: nil, S2: nil, C1: nil, C2: nil, C: nil,
	}
}

//// VerifyEquivalenceORLog
// Takes in Base1, Result1, Base2, Result2, Base3, Result3, and a proof
//
// Verifies a proof that either knowledge of x s.t.
// 	- log_{Base1} Result1 == log_{Base2} Result2 == x OR
// 	- log_{Base3} Result3 == x
//
// For proof of well-formedness:
//  - Base1 = H
//  - Result1 = A_i
//  - Base2 = PK_i
//  - Result2 = B_i
//  - Base3 = H
//  - Result3 = PK_i
//  Will prove either you know r_i for this TX, or you signed off on the transaction
//
// For Rerandomization during Auditing:
//  - Base1 = A_i
//  - Result1 = B_i
//  - Base2 = H
//  - Result2 = PK_i
//  - Base3 = H
//  - Result3 = C_i/A_i = ec.Add(C_i.X, C_i.Y, A_i.X, new(big.Int).Neg(A_i.Y))
//  Will prove either that the value commited to in A_i is 0 so you know your secret key sk_i,
//  or that you did participate in this transaction and know r'-r where r' is used in re-randomized
//  commitment and r is the original randomness in A_i.
//
// Returns whether the proof is valid or not
func VerifyEquivalenceORLog(Base1 ECPoint, Result1 ECPoint,
	Base2 ECPoint, Result2 ECPoint,
	Base3 ECPoint, Result3 ECPoint,
	proof EquivORLogProof) bool {

	stringToHash := Base1.X.String() + "||" + Base1.Y.String() + ";" +
		Base2.X.String() + "||" + Base2.Y.String() + ";" +
		Base3.X.String() + "||" + Base3.Y.String() + ";" +
		Result1.X.String() + "||" + Result1.Y.String() + ";" +
		Result2.X.String() + "||" + Result2.Y.String() + ";" +
		Result3.X.String() + "||" + Result3.Y.String() + ";" +
		proof.B1u.X.String() + "||" + proof.B1u.Y.String() + ";" +
		proof.B2u.X.String() + "||" + proof.B2u.Y.String() + ";" +
		proof.B3u.X.String() + "||" + proof.B3u.Y.String() + ";"

	s256 := sha256.New()
	s256.Write([]byte(stringToHash))
	calculatedC := new(big.Int).SetBytes(s256.Sum(nil))

	if proof.C.Cmp(calculatedC) != 0 {
		// if the prover didn't calculate C as we did, return false
		Dprintf("Wrong c calculated: %v proof: %v\n", calculatedC, proof.C)
		return false
	}

	if proof.C.Cmp(
		new(big.Int).Mod(new(big.Int).Add(proof.C1, proof.C2), EC.N)) != 0 {
		// if c1+c2 != c, return false
		Dprintf("Wrong c1+c2: %v+%v proof: %v\n", proof.C1, proof.C2, proof.C)
		return false
	}

	// checking for equivalence values means using the same c1,s1 combo

	// check the B1 side
	h1c1X, h1c1Y := EC.C.ScalarMult(Result1.X, Result1.Y, proof.C1.Bytes())
	rhs1X, rhs1Y := EC.C.Add(h1c1X, h1c1Y, proof.B1u.X, proof.B1u.Y)
	lhs1X, lhs1Y := EC.C.ScalarMult(Base1.X, Base1.Y, proof.S1.Bytes())

	if lhs1X.Cmp(rhs1X) != 0 && lhs1Y.Cmp(rhs1Y) != 0 {
		Dprintf("lhs and rhs don't match: \nlhs: %v %v \nrhs: %v %v\n",
			lhs1X, lhs1Y, rhs1X, rhs1Y)
		return false
	}

	// check the B2 side
	h2c2X, h2c2Y := EC.C.ScalarMult(Result2.X, Result2.Y, proof.C1.Bytes())
	rhs2X, rhs2Y := EC.C.Add(h2c2X, h2c2Y, proof.B2u.X, proof.B2u.Y)
	lhs2X, lhs2Y := EC.C.ScalarMult(Base2.X, Base2.Y, proof.S1.Bytes())

	if lhs2X.Cmp(rhs2X) != 0 && lhs2Y.Cmp(rhs2Y) != 0 {
		return false
	}

	// checking that the log value is correct

	// check the B3 side
	h3c3X, h3c3Y := EC.C.ScalarMult(Result3.X, Result3.Y, proof.C2.Bytes())
	rhs3X, rhs3Y := EC.C.Add(h3c3X, h3c3Y, proof.B3u.X, proof.B3u.Y)
	lhs3X, lhs3Y := EC.C.ScalarMult(Base3.X, Base3.Y, proof.S2.Bytes())

	if lhs3X.Cmp(rhs3X) != 0 && lhs3Y.Cmp(rhs3Y) != 0 {
		return false
	}
	return true
}

type ConsistencyProof struct {
	A1 ECPoint
	A2 ECPoint
	C  *big.Int
	R1 *big.Int
	R2 *big.Int
}

func ProveConsistency(
	P1, P2, pk ECPoint, value, randomness *big.Int) *ConsistencyProof {
	modValue := new(big.Int).Mod(value, EC.N)
	pc := ECPedersen{EC.C, EC.G, EC.H}

	// do a quick correctness check to ensure the value we are testing and the
	// randomness are correct
	if !P1.Equal(pc.CommitWithR(value, randomness)) {
		fmt.Println("Tsk tsk tsk, lying about our commitments, ay?")
	}

	if !P2.Equal(pk.Mult(randomness)) {
		fmt.Println(
			"Such disgrace! Lying about our Randomness Token! The audacity!")
	}

	u1, err := rand.Int(rand.Reader, EC.N)
	check(err)

	u2, err2 := rand.Int(rand.Reader, EC.N)
	check(err2)

	A1 := pc.CommitWithR(u1, u2)
	A2 := pk.Mult(u2)

	stringToHash := EC.G.X.String() + "," + EC.G.Y.String() + ";" +
		EC.H.X.String() + "," + EC.H.Y.String() + ";" +
		P1.X.String() + "," + P1.Y.String() + ";" +
		P2.X.String() + "," + P2.Y.String() + ";" +
		pk.X.String() + "," + pk.Y.String() + ";" +
		A1.X.String() + "," + A1.Y.String() + ";" +
		A2.X.String() + "," + A2.Y.String()

	hashed := sha256.Sum256([]byte(stringToHash))
	C := new(big.Int).SetBytes(hashed[:])

	R1 := new(big.Int).Add(u1, new(big.Int).Mul(modValue, C))
	R2 := new(big.Int).Add(u2, new(big.Int).Mul(randomness, C))
	R1.Mod(R1, EC.N)
	R2.Mod(R2, EC.N)

	return &ConsistencyProof{A1, A2, C, R1, R2}
}

func VerifyConsistency(P1, P2, pk ECPoint, proof *ConsistencyProof) bool {
	pc := ECPedersen{EC.C, EC.G, EC.H}

	stringToHash := EC.G.X.String() + "," + EC.G.Y.String() + ";" +
		EC.H.X.String() + "," + EC.H.Y.String() + ";" +
		P1.X.String() + "," + P1.Y.String() + ";" +
		P2.X.String() + "," + P2.Y.String() + ";" +
		pk.X.String() + "," + pk.Y.String() + ";" +
		proof.A1.X.String() + "," + proof.A1.Y.String() + ";" +
		proof.A2.X.String() + "," + proof.A2.Y.String()

	hashed := sha256.Sum256([]byte(stringToHash))
	C := new(big.Int).SetBytes(hashed[:])

	if C.Cmp(proof.C) != 0 {
		Dprintf("C calculation is incorrect\n")
		return false
	}

	lhs1 := pc.CommitWithR(proof.R1, proof.R2)
	rhs1p := P1.Mult(C)
	rhs1 := proof.A1.Add(rhs1p)

	if !lhs1.Equal(rhs1) {
		Dprintf("P1 comparison is failing\n")
		return false
	}

	lhs2 := pk.Mult(proof.R2)
	rhs2p := P2.Mult(C)
	rhs2 := proof.A2.Add(rhs2p)

	if !lhs2.Equal(rhs2) {
		Dprintf("P2 comparison is failing\n")
		return false
	}

	return true
}

///////////////////////
// RANGE PROOFS

type RangeProofTuple struct {
	C ECPoint
	S *big.Int
}

type RangeProof struct {
	ProofAggregate ECPoint
	ProofE         *big.Int
	ProofTuples    []RangeProofTuple
}

type ProverInternalData struct {
	Rpoints  []ECPoint
	Bpoints  []ECPoint
	kScalars []*big.Int
	vScalars []*big.Int
}

// ProofGenA takes in a waitgroup, index and bit
// returns an Rpoint and Cpoint, and the k value bigint
func ProofGenA(
	wg *sync.WaitGroup, idx int, bit bool, s *ProverInternalData) {

	defer wg.Done()
	var err error

	//	R := s.Rpoints[idx]
	//	B := s.Bpoints[idx]
	//	k := stuff.kScalars[index]
	//	v := stuff.vScalars[index]

	if !bit { // If bit is 0, just make a random R = k*H
		s.kScalars[idx], err = rand.Int(rand.Reader, EC.C.Params().N) // random k
		check(err)
		s.Rpoints[idx].X, s.Rpoints[idx].Y =
			EC.KC.ScalarBaseMultH(s.kScalars[idx].Bytes()) // R is k*H
	} else { // if bit is 1, actually do stuff

		// get a random ri
		s.vScalars[idx], err = rand.Int(rand.Reader, EC.C.Params().N)
		check(err)
		// get R as H*ri... what is KC..?
		s.Rpoints[idx].X, s.Rpoints[idx].Y =
			EC.KC.ScalarBaseMultH(s.vScalars[idx].Bytes())

		// B is htothe[index] plus partial R
		s.Bpoints[idx].X, s.Bpoints[idx].Y =
			EC.C.Add(H2tothe[idx].X, H2tothe[idx].Y,
				s.Rpoints[idx].X, s.Rpoints[idx].Y)

			// random k
		s.kScalars[idx], err = rand.Int(rand.Reader, EC.C.Params().N)
		check(err)

		// make k*H for hashing
		tempX, tempY := EC.KC.ScalarBaseMultH(s.kScalars[idx].Bytes())

		// Hash of temp point (why the whole thing..?
		hash := sha256.Sum256(append(tempX.Bytes(), tempY.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:])
		ei.Mod(ei, EC.C.Params().N)
		s.Rpoints[idx].X, s.Rpoints[idx].Y =
			EC.C.ScalarMult(s.Bpoints[idx].X, s.Bpoints[idx].Y, ei.Bytes())
	}
	//	fmt.Printf("loop %d\n", idx)

	return
}

// ProofGenB takes waitgroup, index, bit, along with the data to operate on
func ProofGenB(
	wg *sync.WaitGroup, idx int, bit bool, e0 *big.Int, data *ProverInternalData) {

	defer wg.Done()

	if !bit {
		// choose a random value from the integers mod prime
		j, err := rand.Int(rand.Reader, EC.C.Params().N)
		check(err)

		m2 := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(idx)), EC.C.Params().N)
		//		m2 := big.NewInt(1 << uint(idx))
		em2 := new(big.Int).Mul(e0, m2)
		em2.Mod(em2, EC.C.Params().N)

		rhsX, rhsY := EC.C.ScalarBaseMult(em2.Bytes())

		lhsX, lhsY := EC.KC.ScalarBaseMultH(j.Bytes())

		totX, totY := EC.C.Add(lhsX, lhsY, rhsX, rhsY)

		hash := sha256.Sum256(append(totX.Bytes(), totY.Bytes()...))
		ei := new(big.Int).SetBytes(hash[:]) // get ei
		ei.Mod(ei, EC.C.Params().N)

		inverseEI := new(big.Int).ModInverse(ei, EC.C.Params().N)

		data.vScalars[idx] = new(big.Int).Mul(inverseEI, data.kScalars[idx])

		// set the C point for this index to R* inv ei
		data.Bpoints[idx] = data.Rpoints[idx].Mult(inverseEI)

		// s = k + (kValues[i] * e0) * inverse ei
		data.kScalars[idx] = j.Add(
			j, new(big.Int).Mul(data.kScalars[idx], new(big.Int).Mul(e0, inverseEI)))

	} else { // bit is 1, don't do anything
		// s is k + e0*v

		data.kScalars[idx] = new(big.Int).Add(
			data.kScalars[idx], new(big.Int).Mul(e0, data.vScalars[idx]))
	}

	return
}

/// RangeProof
// Implementation details from:
// https://blockstream.com/bitcoin17-final41.pdf
// NOTE: To be consistent with our use of Pedersen commitments, we switch the G and H values
// from the above description
//
// Takes in a value and randomness used in a commitment, and produces a proof that
// our value is in range 2^64.
// Range proofs uses ring signatures from Chameleon hashes and Pedersen Commitments
// to do commitments on the bitwise decomposition of our value.
//
func RangeProverProve(value *big.Int) (*RangeProof, *big.Int) {
	proof := RangeProof{}

	// extend or truncate our value to 64 bits, which is the range we are proving
	// If our value is in range, then sum of commitments would equal original commitment
	// else, because of truncation, it will be deemed out of range not be equal

	if value.Cmp(big.NewInt(1099511627776)) == 1 {
		fmt.Printf("val %stoo big, can only prove up to 1099511627776\n",
			value.String())
		return nil, nil
	}

	proofSize := 40
	// check to see if our value is out of range
	if proofSize > 40 || value.Cmp(big.NewInt(0)) == -1 {
		//if so, then we can't play
		Dprintf("** Trying to get a value that is out of range! Range Proof will not work!\n")
		return nil, nil
	}

	stuff := new(ProverInternalData)

	stuff.kScalars = make([]*big.Int, proofSize)
	stuff.Rpoints = make([]ECPoint, proofSize)
	stuff.Bpoints = make([]ECPoint, proofSize)
	stuff.vScalars = make([]*big.Int, proofSize)

	vTotal := big.NewInt(0)
	proof.ProofTuples = make([]RangeProofTuple, proofSize)

	//	 do the loop bValue times
	var wg sync.WaitGroup
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		go ProofGenA(&wg, i, value.Bit(i) == 1, stuff)
	}
	wg.Wait()

	// hash concat of all R values
	rHash := sha256.New()
	for _, rvalue := range stuff.Rpoints {
		rHash.Write(rvalue.X.Bytes())
		rHash.Write(rvalue.Y.Bytes())
	}
	hashed := rHash.Sum(nil)

	e0 := new(big.Int).SetBytes(hashed[:])
	e0.Mod(e0, EC.C.Params().N)

	var AggregatePoint ECPoint
	AggregatePoint.X = new(big.Int)
	AggregatePoint.Y = new(big.Int)

	// go through all 64 part B
	wg.Add(proofSize)
	for i := 0; i < proofSize; i++ {
		go ProofGenB(
			&wg, i, value.Bit(i) == 1, e0, stuff)
	}
	wg.Wait()

	for i := 0; i < proofSize; i++ {
		//		add up to get vTotal scalar
		vTotal.Add(vTotal, stuff.vScalars[i])

		// add points to get AggregatePoint
		AggregatePoint = AggregatePoint.Add(stuff.Bpoints[i])

		// copy data to ProofTuples
		proof.ProofTuples[i].C = stuff.Bpoints[i]
		proof.ProofTuples[i].S = stuff.kScalars[i]
	}

	proof.ProofE = e0
	proof.ProofAggregate = AggregatePoint

	return &proof, vTotal
}

type VerifyTuple struct {
	index  int
	Rpoint ECPoint
}

// give it a proof tuple, proofE.  Get back an Rpoint, and a Cpoint
func VerifyGen(
	idx int, proofE *big.Int, rpt RangeProofTuple, retbox chan VerifyTuple) {

	lhs := new(ECPoint)
	lhs.X, lhs.Y = EC.KC.ScalarBaseMultH(rpt.S.Bytes())

	rhs2 := rpt.C.Add(H2tothe[idx].Neg())

	rhsXYNeg := rhs2.Mult(proofE).Neg()

	//s_i * G - e_0 * (C_i - 2^i * H)
	tot := lhs.Add(rhsXYNeg)

	hash := sha256.Sum256(append(tot.X.Bytes(), tot.Y.Bytes()...))

	e1 := new(big.Int).SetBytes(hash[:])

	var result VerifyTuple
	result.index = idx
	result.Rpoint = rpt.C.Mult(e1)

	retbox <- result

	return
}

func RangeProverVerify(comm ECPoint, proof *RangeProof) bool {
	proofs := proof.ProofTuples

	proofLength := len(proofs)

	Rpoints := make([]ECPoint, len(proofs))

	totalPoint := ECPoint{big.NewInt(0), big.NewInt(0)}

	resultBox := make(chan VerifyTuple, 10) // doubt we'll use even 1

	for i := 0; i < proofLength; i++ {
		// check that proofs are non-nil
		if proof.ProofTuples[i].C.X == nil {
			fmt.Println(proofs)
			panic(fmt.Sprintf("entry %d has nil point", i))
		}
		if proof.ProofTuples[i].S == nil {
			fmt.Println(proofs)
			panic(fmt.Sprintf("entry %d has nil scalar", i))

		}

		// give proof to the verify gorouting
		go VerifyGen(i, proof.ProofE, proof.ProofTuples[i], resultBox)
	}

	for i := 0; i < proofLength; i++ {
		result := <-resultBox

		// only reason we do this is for the hash of the point.
		// could do something commutative here too?
		Rpoints[result.index] = result.Rpoint

		// add to totalpoint here (commutative)
		totalPoint = totalPoint.Add(proof.ProofTuples[i].C)
	}

	rHash := sha256.New()
	for _, rpoint := range Rpoints {
		rHash.Write(rpoint.X.Bytes())
		rHash.Write(rpoint.Y.Bytes())
	}
	calculatedE0 := rHash.Sum(nil)

	if proof.ProofE.Cmp(new(big.Int).SetBytes(calculatedE0[:])) != 0 {
		//fmt.Println("check 1")
		return false
	}

	if !totalPoint.Equal(proof.ProofAggregate) {
		return false
	}

	// TODO
	// This checks that comm and proof Aggregate are equal.  seems "pointless".

	if !comm.Equal(totalPoint) {
		return false
	}

	return true
}

///////////////////////
// KEYGEN

// NewECPrimeGroupKey returns the curve (field),
// Generator 1 x&y, Generator 2 x&y, order of the generators
func NewECPrimeGroupKey() APLCrypto {
	curValue := btcec.S256().Gx
	s256 := sha256.New()
	s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

	potentialXValue := make([]byte, 33)
	binary.LittleEndian.PutUint32(potentialXValue, 2)
	for i, elem := range s256.Sum(nil) {
		potentialXValue[i+1] = elem
	}

	gen2, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
	check(err)

	return APLCrypto{btcec.S256(), btcec.S256(), ECPoint{btcec.S256().Gx,
		btcec.S256().Gy}, ECPoint{gen2.X, gen2.Y}, btcec.S256().N}
}

func (e APLCrypto) KeyGen() (ECPoint, *big.Int) {

	sk, err := rand.Int(rand.Reader, e.N)
	check(err)
	pkX, pkY := e.C.ScalarMult(e.H.X, e.H.Y, sk.Bytes())

	return ECPoint{pkX, pkY}, sk
}

func (e APLCrypto) DeterministicKeyGen(id int) (ECPoint, *big.Int) {
	idb := big.NewInt(int64(id + 1))
	pkX, pkY := e.C.ScalarMult(e.H.X, e.H.Y, idb.Bytes())
	return ECPoint{pkX, pkY}, idb
}

func GenerateH2tothe() []ECPoint {
	Hslice := make([]ECPoint, 64)
	for i, _ := range Hslice {
		// mv := new(big.Int).Exp(new(big.Int).SetInt64(2), big.NewInt(int64(len(bValue)-i-1)), EC.C.Params().N)
		// This does the same thing.
		m := big.NewInt(1 << uint(i))
		Hslice[i].X, Hslice[i].Y = EC.C.ScalarBaseMult(m.Bytes())
	}
	return Hslice
}

func init() {
	EC = NewECPrimeGroupKey()
	H2tothe = GenerateH2tothe()
}
