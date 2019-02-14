package zkledger

import (
	"flag"
	"fmt"
	"math/big"
	"runtime"
	"time"
)

type TXN_TYPE int

const (
	Transfer TXN_TYPE = iota
	Issuance
	Withdrawal
)

var parallelizeVerify = flag.Bool("pv", false, "Parallelize verification")
var reduce = flag.Bool("re", false, "Reduce size of transactions by setting transaction proofs to nil after verification. Only works in distributed setting")

type Entry struct {
	Bank    int
	Comm    ECPoint  // A_i
	RToken  ECPoint  // B_i
	V       *big.Int // unencrypted value for testing and issuance/withdrawal
	R       *big.Int // value for testing
	CommAux ECPoint  // cm_{aux,i},
	BAux    ECPoint  // B_{aux,i} g^v*h^r'
	// Proof of well-formedness (r_i's match, v is 0 or I know sk)
	//WellFormed      EquivORLogProof // "I know x st x = log_h(A_i) = log_{pk_i}(B_i) OR I know y st y = log_h(pk_i)"
	CommConsistency *ConsistencyProof
	AuxConsistency  *ConsistencyProof
	Assets          *DisjunctiveGSPFSProof // "cm_{aux,i}~\sum{cm_col} OR cm_{aux,i}~cm_i"
	RP              *RangeProof            // cm_{aux,i} >= 0
	BAuxR           *big.Int               // Intermediately hold r here so I can generate the Range Proof outside of createLocal (holding the lock in ledger)
	SKProof         *GSPFSProof            // Proof of knowledge of SK for issuance (issuer) or withdrawal (Bank)
}

// Well-formedness
// --Proof that A_i and B_i are consistent (same r)--
// Proof that value is 0 for not-involved banks

// Proof of assets
// Proof that cm_{aux,i}~cm_i when v >= 0
// Proof that cm_{aux_i}~\sum{cm_col} when v < 0
// Range proof on cm_{aux,i}

// New consistency proofs:
// Proof that cm_i and B_i are consistent  (same r)
// Proof that cm_{aux,i} and B_{aux,i} are consistent  (same r')

type EncryptedTransaction struct {
	Index      int ``
	TS         time.Time
	Type       TXN_TYPE
	Sender     int // testing
	Receiver   int // testing
	Entries    []Entry
	skipVerify bool // Only for testing; default false
}

func (etx *EncryptedTransaction) reduce() {
	if *reduce {
		// Delete proofs
		for i := 0; i < len(etx.Entries); i++ {
			e := &etx.Entries[i]
			e.CommConsistency = nil
			e.AuxConsistency = nil
			e.Assets = nil
			e.RP = nil
			e.SKProof = nil
		}
	}
}

// Only for testing
func (e *EncryptedTransaction) print_decrypted() {
	Dprintf("ETX %v\t{", e.Index)
	for i := 0; i < len(e.Entries); i++ {
		ent := &e.Entries[i]
		Dprintf("b%v :[%#v] \n", i, ent)
	}
	Dprintf("}\n")
}

func (en *Entry) verify(pks []ECPoint, CommCache ECPoint, RTokenCache ECPoint, eidx int, i int, debug string) bool {
	// Check consistency proofs
	if !VerifyConsistency(en.Comm, en.RToken, pks[i], en.CommConsistency) {
		Dprintf(" [%v] ETX %v Failed verify consistency comm entry %v %#v\n", debug, eidx, i, en)
		return false
	}
	if !VerifyConsistency(en.CommAux, en.BAux, pks[i], en.AuxConsistency) {
		Dprintf(" [%v] ETX %v Failed verify consistency aux entry %v\n", debug, eidx, i)
		return false
	}
	// Check Proof of Assets
	Base1 := en.CommAux.Add(CommCache.Add(en.Comm).Neg())
	Result1 := en.BAux.Add(RTokenCache.Add(en.RToken).Neg())
	Result2 := en.CommAux.Add(en.Comm.Neg())
	if !VerifyDisjunctive(Base1, Result1, EC.H, Result2, en.Assets) {
		fmt.Printf("  [%v] %v/%v Base1: %v\n", debug, eidx, i, Base1)
		fmt.Printf("  [%v] %v/%v Result1: %v\n", debug, eidx, i, Result1)
		fmt.Printf("  [%v] %v/%v Result2: %v\n", debug, eidx, i, Result2)
		fmt.Printf("  [%v] ETX %v Failed verify left side of proof of assets entry %v\n", debug, eidx, i)
		return false
	}
	//   Range Proof
	if !RangeProverVerify(en.CommAux, en.RP) {
		Dprintf("  [%v] %v/%v Range Proof: %v\n", debug, eidx, i, en.RP)
		Dprintf("  [%v] ETX %v Failed verify the range proof on CommAux %v\n", debug, eidx, i)
		return false
	}
	return true
}

func (e *EncryptedTransaction) Verify(pks []ECPoint, CommCache []ECPoint, RTokenCache []ECPoint, debug string) bool {
	if e.skipVerify {
		return true
	}
	g := GSPFS{curve: EC.C, ExponentPrime: EC.N, Generator: EC.H}
	// Issuance
	if e.Type == Issuance {
		en := &e.Entries[e.Sender]
		if en.V.Cmp(big.NewInt(0)) <= 0 {
			Dprintf(" [%v] ETX %v Failed verify; issuance transaction values must be positive\n",
				debug, e.Index)
			return false
		}
		// Check proof of knowledge of sk_{asset issuer}
		if !g.Verify(pks[len(pks)-1], en.SKProof) {
			Dprintf("[%v] ETX %v Failed issuance: proof of knowledge of SK\n", debug, e.Index)
			return false
		}
		return true
	}
	// Withdrawal
	if e.Type == Withdrawal {
		en := &e.Entries[e.Sender]
		if en.V.Cmp(big.NewInt(0)) > 0 {
			Dprintf(" [%v] ETX %v Failed verify; withdrawal transaction values must be negative\n",
				debug, e.Index)
			return false
		}
		// Check proof of knowledge of sk_{bank}
		if !g.Verify(pks[e.Sender], en.SKProof) {
			Dprintf(" [%v] ETX %v Failed withdrawal: proof of knowledge of SK\n", debug, e.Index)
			return false
		}
		return true
	}
	// Transfer

	if (len(pks) - 1) != len(e.Entries) { // we subtract 1 from len(pks) because the last entry is the issuer's key
		fmt.Println("Length pks: %v, length entries: %v\n", len(pks)-1, len(e.Entries))
		panic("invalid sizes")
	}
	commitmentSum := EC.Zero()
	rets := make(chan bool)
	for i := 0; i < len(e.Entries); i++ {
		en := &e.Entries[i]
		commitmentSum = commitmentSum.Add(en.Comm)
		if en.Bank != i {
			Dprintf(" [%v] ETX %v Failed verify mismatching bank %#v\n", debug, e.Index, en)
			return false
		}
		if *parallelizeVerify && runtime.NumCPU() > 1 {
			go func(i int) {
				x := en.verify(pks, CommCache[i], RTokenCache[i], e.Index, i, debug)
				if x != true {
					fmt.Printf("[%v] ETX %v Failed entry verification; %v spending %v receiving %v amt\n", debug, e.Index, e.Sender, e.Receiver, e.Entries[e.Sender].V)
				}
				rets <- x
			}(i)
		} else {
			if !en.verify(pks, CommCache[i], RTokenCache[i], e.Index, i, debug) {
				return false
			}
		}
	}
	if *parallelizeVerify && runtime.NumCPU() > 1 {
		success := true
		for i := 0; i < len(e.Entries); i++ {
			if r := <-rets; !r {
				success = false
			}
		}
		close(rets)
		if !success {
			return false
		}
	}

	// to verify the zero sum commitments we add up all the values and make sure it adds to 0
	/*
		if !VerifyZeroSumCommitments(*e, gsp) {
			Dprintf(" [%v] ETX %v Failed verify zero sum\n", debug, e.Index)
			return false
		}*/
	if commitmentSum.X.Cmp(new(big.Int).SetInt64(0)) != 0 && commitmentSum.Y.Cmp(new(big.Int).SetInt64(0)) != 0 {
		Dprintf(" [%v] ETX %v Failed verify zero sum\n", debug, e.Index)
		return false
	}

	return true
}
