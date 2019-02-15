package zkledger

import (
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestSimpleSumAudit(t *testing.T) {
	error := false
	s := SetupTest(2, 1, 500)
	defer FinishTest(s)
	if len(s.L.Transactions) != 3 {
		t.Errorf("Ledger Process() didn't work")
		error = true
	}
	bank_val, _ := s.B[1].answerSum()
	audit_val, x := s.A.computeSum(1)
	if x != true {
		t.Fatalf("Auditing did not work out! Bank:%v Auditor:%v", bank_val, audit_val)
		error = true
	}
	tmp := big.NewInt(600)
	if audit_val.Cmp(tmp) != 0 {
		t.Fatalf("Bad audit value, should be 600 auditor: %v\n", audit_val)
	}
	if audit_val.Cmp(bank_val) != 0 {
		t.Fatalf("Mismatched answers to sum for bank 1, should be 600 auditor: %v, bank: %v\n",
			audit_val, bank_val)
		error = true
	}

	bank_val, _ = s.B[0].answerSum()
	audit_val, x = s.A.computeSum(0)
	if x != true {
		t.Fatalf("Auditing did not work out! Bank:%v Auditor:%v", bank_val, audit_val)
		error = true
	}
	if audit_val.Cmp(big.NewInt(400)) != 0 {
		t.Fatalf("Bad audit value, should be 400 auditor: %v\n", audit_val)
		error = true
	}
	if audit_val.Cmp(bank_val) != 0 {
		t.Fatalf("Mismatched answers to sum for bank 0, should be -100 auditor: %v, bank: %v\n",
			audit_val, bank_val)
		error = true
	}
	if !error {
		fmt.Printf("Passed TestSimpleSumAudit\n")
	}
}

func TestAuditWithIssuance(t *testing.T) {
	error := false
	s := SetupTest(2, 0, 50)
	defer FinishTest(s)
	v := big.NewInt(50)
	//s.B[0].Issue(v)
	time.Sleep(20 * time.Millisecond)
	bank_val, _ := s.B[0].answerSum()
	audit_val, x := s.A.computeSum(0)
	if x != true {
		t.Fatalf("Auditing did not work out! Bank:%v Auditor:%v", bank_val, audit_val)
		error = true
	}
	if audit_val.Cmp(v) != 0 {
		t.Fatalf("Bad audit value, should be 50 auditor: %v\n", audit_val)
	}
	if audit_val.Cmp(bank_val) != 0 {
		t.Fatalf("Mismatched answers to sum for bank 0, should be 50 auditor: %v, bank: %v\n",
			audit_val, bank_val)
		error = true
	}
	v = big.NewInt(25)
	s.B[0].CreateEncryptedTransaction(1, v)
	time.Sleep(20 * time.Millisecond)
	bank_val, _ = s.B[0].answerSum()
	audit_val, x = s.A.computeSum(0)
	if x != true {
		t.Fatalf("Auditing did not work out! Bank:%v Auditor:%v", bank_val, audit_val)
		error = true
	}
	if audit_val.Cmp(v) != 0 {
		t.Fatalf("Bad audit value, should be 25 auditor: %v\n", audit_val)
	}
	if audit_val.Cmp(bank_val) != 0 {
		t.Fatalf("Mismatched answers to sum for bank 0, should be 25 auditor: %v, bank: %v\n",
			audit_val, bank_val)
		error = true
	}

	if !error {
		fmt.Printf("Passed TestAuditWithIssuance\n")
	}
}

func TestHerfindahl(t *testing.T) {
	s := SetupTest(2, 0, 10)
	defer FinishTest(s)
	hIndex, err := s.A.Herfindahl(true, nil)
	if err != nil {
		t.Fatalf("Couldn't calculate concentrations some bank didn't verify\n")
	}
	if hIndex.Cmp(big.NewRat(1, 2)) != 0 {
		t.Fatalf("Banks do not have right Herfindahl Index %v\n", hIndex)
	}

	fmt.Println("Passed TestHerfindahl")
}

func TestBadAudit(t *testing.T) {
	s := SetupTest(2, 1, 500)
	defer FinishTest(s)
	if len(s.L.Transactions) != 3 {
		t.Errorf("Ledger Process() didn't work")
	}

	// Reach in and change the bank's answer
	tmp := big.NewInt(2)
	var tx *Transaction
	for _, v := range s.B[1].transactions {
		tx = v
		break
	}
	tx.value.Set(tmp)
	s.B[1].ValueCache.Set(tmp)

	bank_val, _ := s.B[1].answerSum()
	audit_val, x := s.A.computeSum(1)
	if x == true {
		t.Fatalf("Auditing should have failed %v %v", bank_val, audit_val)
	}
	if audit_val.Cmp(tmp) != 0 {
		t.Fatalf("Bad audit value, should be 2 auditor: %v\n", audit_val)
	}
	if audit_val.Cmp(bank_val) < 0 {
		t.Fatalf("Mismatched answers to sum for bank 1, should be 2 auditor: %v, bank: %v\n",
			audit_val, bank_val)
	}
	fmt.Printf("Passed TestBadAudit\n")
}

func TestThreeBankAudit(t *testing.T) {
	nb := 3
	ntx := 2
	initialAmount := 500
	s := SetupTest(nb, ntx, int64(initialAmount))
	defer FinishTest(s)
	if len(s.L.Transactions) != (ntx + nb) {
		t.Errorf("Ledger Process() didn't work")
	}
	for i := 0; i < nb; i++ {
		if len(s.B[i].local_ledger.Transactions) != ntx+nb {
			t.Fatalf("Bank %v has not gotten all %v transactions.  Has %v", i, nb+ntx, len(s.B[i].local_ledger.Transactions))
		}
	}
	audit_val, x := s.A.computeSum(0)
	if x != true {
		for i := 0; i < nb; i++ {
			s.B[i].print_transactions()
		}
		t.Fatalf("Auditing failed %v", audit_val)
	}
	fmt.Printf("Passed TestThreeBankAudit\n")
}

func benchmarkClearSum(rows int, b *testing.B) {
	s := SetupTest(10, rows, 500)
	defer FinishTest(s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		audit := i % 10
		s.A.computeClearSum(audit)
	}
}

func BenchmarkClearSum1000x(b *testing.B) { benchmarkClearSum(1000, b) }
func BenchmarkClearSum10000(b *testing.B) { benchmarkClearSum(10000, b) }

func benchmarkEncSum(rows int, b *testing.B) {
	s := SetupTest(10, rows, 500)
	defer FinishTest(s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		audit := i % 10
		s.A.computeSum(audit)
	}
}

func BenchmarkEncSum100x(b *testing.B)   { benchmarkEncSum(100, b) }
func BenchmarkEncSum1000x(b *testing.B)  { benchmarkEncSum(1000, b) }
func xBenchmarkEncSum10000(b *testing.B) { benchmarkEncSum(10000, b) }
