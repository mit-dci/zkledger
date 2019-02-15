package apl

import (
	"fmt"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/mit-dci/zksigma"
)

func TestSetupBanks(t *testing.T) {
	n := 2
	pki := &PKI{}
	pki.MakeTest(n)
	l := MakeLedger(n)
	a := MakeAuditor(n, pki)
	banks := SetupLocalBanks(n, l, pki)
	l.Banks = make([]BankClient, n)
	a.banks = make([]BankClient, n)
	for i := 0; i < n; i++ {
		l.Banks[i] = banks[i]
		a.banks[i] = banks[i]
	}
	if len(l.Banks) != n {
		t.Errorf("Incorrect ledger setup: %v banks\n", len(l.Banks))
	}
	for i := 0; i < n; i++ {
		if banks[i].id != i {
			t.Errorf("Bad bank setup %v should be %v\n", banks[i].id, i)
		}
	}
	fmt.Printf("Passed TestSetupBanks\n")
}

func TestSetupTest(t *testing.T) {
	s := SetupTest(2, 0, 500)
	defer FinishTest(s)
	if len(s.B[0].transactions) != 1 { // my issuance transaction
		t.Fatalf("Bank 0 should have 1 issuance transaction; instead has %v\n", len(s.B[0].transactions))
	}
	if len(s.B[0].local_ledger.Transactions) != 2 {
		s.B[0].DumpLedger(nil, nil)
		t.Fatalf("Bank 0 should have 2 in local ledger; instead has %v\n", len(s.B[0].local_ledger.Transactions))
	}
	if len(s.B[1].transactions) != 1 { // my issuance transaction
		t.Fatalf("Bank 1 should have 1 issuance transaction; instead has %v\n", len(s.B[1].transactions))
	}
	if len(s.B[1].local_ledger.Transactions) != 2 {
		s.B[1].DumpLedger(nil, nil)
		t.Fatalf("Bank 1 should have 2 in local ledger; instead has %v\n", len(s.B[1].local_ledger.Transactions))
	}
	time.Sleep(5 * time.Millisecond)
	if len(s.A.local_ledger.Transactions) != 2 {
		t.Fatalf("Auditor should have 2 in local ledger; instead has %v\n", len(s.A.local_ledger.Transactions))
	}
}

func TestBanksWithTransaction(t *testing.T) {
	s := SetupTest(2, 1, 500)
	defer FinishTest(s)
	s.B[0].mu.Lock()
	defer s.B[0].mu.Unlock()
	s.B[1].mu.Lock()
	defer s.B[1].mu.Unlock()
	s.A.mu.Lock()
	defer s.A.mu.Unlock()

	if len(s.B[0].transactions) != 2 { //incorporating the issuance transactions
		t.Fatalf("Bank 0 should have 2 transactions; instead has %v\n", len(s.B[0].transactions))
	}
	if len(s.B[0].local_ledger.Transactions) != 3 {
		s.B[0].DumpLedger(nil, nil)
		t.Fatalf("Bank 0 should have 3 in local ledger; instead has %v\n", len(s.B[0].local_ledger.Transactions))
	}
	var tx *Transaction
	var ok bool
	if tx, ok = s.B[0].transactions[2]; !ok {
		t.Fatalf("Bank 0 should have index 0 transaction %v\n", s.B[0].transactions)
	}
	if tx.value.Cmp(big.NewInt(-100)) != 0 {
		t.Fatalf("Bank 0 should have one -100 transaction %v\n", s.B[0].transactions[1])
	}

	if len(s.B[1].transactions) != 2 {
		s.B[1].print_transactions()
		t.Fatalf("Bank 1 should have 2 transactions; instead has %v\n", len(s.B[1].transactions))
	}
	if len(s.B[1].local_ledger.Transactions) != 3 {
		t.Fatalf("Bank 1 should have 3 in local ledger; instead has %v\n", len(s.B[1].local_ledger.Transactions))
	}
	if tx, ok = s.B[1].transactions[2]; !ok {
		t.Fatalf("Bank 1 should have index 1 transaction %v\n", s.B[1].transactions)
	}
	if tx.value.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("Bank 1 should have one 100 transaction %v\n", *s.B[1].transactions[2])
	}

	if len(s.A.local_ledger.Transactions) != 3 {
		t.Fatalf("Auditor should have 3 in local ledger; instead has %v\n", len(s.A.local_ledger.Transactions))
	}

	// Test RToken
	rt := s.L.Transactions[2].Entries[1].RToken // we did two issuances, so the ledger should have a total of 3
	tx, ok = s.B[1].transactions[2]
	if !ok {
		t.Fatalf("Bank 1 should have index 1 transaction %v\n", s.B[1].transactions)
	}
	if !zksigma.VerifyR(rt, s.B[1].pki.Get(1), tx.r) {
		t.Errorf("Bad RToken %v\n", rt)
	} else {
		fmt.Printf("Passed TestBanksWithTransaction\n")
	}
}

func TestOutOfOrderBanks(t *testing.T) {
	s := SetupTest(2, 0, 500)
	defer FinishTest(s)
	b := s.B[0]
	entries := make([]Entry, 2)
	for i := 0; i < 2; i++ {
		entries[i].CommAux = zksigma.Zero
		entries[i].Comm = zksigma.Zero
		entries[i].RToken = zksigma.Zero
	}
	b.Notify(&EncryptedTransaction{Index: 3, skipVerify: true, Entries: entries}, nil)
	if b.lastSeen != 1 { // should have only seen issuance
		t.Errorf("Bank shouldn't have seen anything yet\n")
	}
	x, ok := <-b.receivedTxns
	if !ok {
		t.Errorf("Bank shouldn't have processed this yet, should be something in channel\n")
	}
	if x.Index != 3 {
		t.Errorf("Wrong transaction from channel.\n")
	}
	b.receivedTxns <- x
	if len(b.local_ledger.Transactions) != 2 {
		t.Errorf("Bank should not have processed transaction\n")
	}
	if b.lastSeen != 1 {
		t.Errorf("Bank shouldn't have seen anything yet\n")
	}
	b.Notify(&EncryptedTransaction{Index: 2, skipVerify: true, Entries: entries}, nil)
	time.Sleep(10 * time.Millisecond)
	if len(b.local_ledger.Transactions) != 4 {
		t.Errorf("Bank should have processed both transactions\n")
	}
	if b.lastSeen != 3 {
		t.Errorf("Bank should have seen two transactions %v\n", b.lastSeen)
	} else {
		fmt.Printf("Passed TestOutOfOrderBanks\n")
	}
}

func TestManyConcurrent(t *testing.T) {
	n := 5
	s := SetupTest(n, 0, 5000)
	defer FinishTest(s)
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			s.B[i%n].CreateEncryptedTransaction((i+1)%n, big.NewInt(10))
			wg.Done()
		}(i)
		wg.Wait()
	}

	// Wait for transactions to get sent to everyone
	time.Sleep(20 * time.Millisecond)
	fmt.Printf("Passed TestManyConcurrent\n")
}

func TestConcurrentCreate(t *testing.T) {
	s := SetupTest(2, 0, 500)
	defer FinishTest(s)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			s.B[i%2].CreateEncryptedTransaction((i+1)%2, big.NewInt(10))
			wg.Done()
		}(i)
		wg.Wait()
	}

	StopWhen(s, 11)
	Wait(s)

	l := s.L
	b0 := s.B[0]
	b1 := s.B[1]
	if len(l.Transactions) != 12 {
		t.Errorf("Ledger doesn't have all transactions %v\n", len(l.Transactions))
	}
	if len(b0.transactions) != 11 {
		t.Errorf("Bank 0 doesn't have all transactions %v\n", len(b0.transactions))
	}
	if len(b1.transactions) != 11 {
		t.Errorf("Bank 1 doesn't have all transactions %v\n", len(b1.transactions))
	}
	audit_val, x := s.A.computeSum(0)
	if x != true {
		t.Errorf("Bank 0 didn't verify audit\n")
	}
	if audit_val.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("Wrong audit value for bank 0 %v\n", audit_val)
	}
	fmt.Printf("Passed TestConcurrentCreate\n")
}

func TestIssuance(t *testing.T) {
	s := SetupTest(2, 0, 50)
	defer FinishTest(s)
	v := big.NewInt(50)
	etx := s.L.Transactions[1] //Issue(v)
	if etx.Sender != 1 {
		t.Errorf("Wrong bank %v\n", etx.Sender)
	}
	en := etx.Entries[1]
	if en.V.Cmp(v) != 0 {
		t.Errorf("Wrong amount %v\n", etx.Sender)
	}
	x := make([]zksigma.ECPoint, 0)
	if !etx.Verify(s.B[0].pki.PK, x, x, "") { // pass in the first banks public keys for now
		t.Errorf("Didn't verify %v\n", etx)
	} else {
		fmt.Printf("Passed TestIssuance\n")
	}
}

func TestWithdrawal(t *testing.T) {
	s := SetupTest(2, 0, 500)
	defer FinishTest(s)
	v := big.NewInt(-50)
	etx := s.B[1].Withdraw(v, nil)
	if etx.Sender != 1 {
		t.Errorf("Wrong bank %v\n", etx.Sender)
	}
	en := etx.Entries[1]
	if en.V.Cmp(v) != 0 {
		t.Errorf("Wrong amount %v\n", etx.Sender)
	}
	x := make([]zksigma.ECPoint, 0)
	if !etx.Verify(s.B[0].pki.PK, x, x, "") {
		t.Errorf("Didn't verify %v\n", etx)
	} else {
		fmt.Printf("Passed TestWithdraw\n")
	}
}

func TestVerifyTxn(t *testing.T) {
	bnum := 10
	s := SetupTest(bnum, 0, 1000)
	defer FinishTest(s)

	// Need a copy of these because CreateEncryptedTransaction will
	// send it to the ledger, which will cause each bank to process
	// it, updating intermediate datastructures and no longer making
	// it valid.
	commsCache := make([]zksigma.ECPoint, bnum)
	rtokenCache := make([]zksigma.ECPoint, bnum)
	for i := 0; i < bnum; i++ {
		commsCache[i] = zksigma.ECPoint{big.NewInt(0).Set(s.B[0].CommsCache[i].X), big.NewInt(0).Set(s.B[0].CommsCache[i].Y)}
		rtokenCache[i] = zksigma.ECPoint{big.NewInt(0).Set(s.B[0].RTokenCache[i].X), big.NewInt(0).Set(s.B[0].RTokenCache[i].Y)}
	}
	etx := s.B[0].CreateEncryptedTransaction(1, big.NewInt(1))
	v := etx.Verify(s.B[0].pki.PK, commsCache, rtokenCache, "")
	if !v {
		t.Errorf("Could not verify txn\n")
	} else {
		fmt.Printf("Passed TestVerifyTxn\n")
	}
}

func BenchmarkAuditOneBank(b *testing.B) {
	s := SetupTest(2, 1000, 500)
	defer FinishTest(s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.B[0].answerSum()
	}
}

func BenchmarkVerifyTwoBanks(b *testing.B)        { benchmarkVerify(2, b) }
func BenchmarkVerifyFourBanks(b *testing.B)       { benchmarkVerify(4, b) }
func BenchmarkVerifySixBanks(b *testing.B)        { benchmarkVerify(6, b) }
func BenchmarkVerifyEightBanks(b *testing.B)      { benchmarkVerify(8, b) }
func BenchmarkVerifyTenBanks(b *testing.B)        { benchmarkVerify(10, b) }
func BenchmarkVerifyTwelveBanks(b *testing.B)     { benchmarkVerify(12, b) }
func BenchmarkVerifyFourteenBanks(b *testing.B)   { benchmarkVerify(14, b) }
func BenchmarkVerifySixteenBanks(b *testing.B)    { benchmarkVerify(16, b) }
func BenchmarkVerifyEighteenBanks(b *testing.B)   { benchmarkVerify(18, b) }
func BenchmarkVerifyTwentyBanks(b *testing.B)     { benchmarkVerify(20, b) }
func BenchmarkVerifyTwentyFourBanks(b *testing.B) { benchmarkVerify(24, b) }
func BenchmarkVerifyThirtyBanks(b *testing.B)     { benchmarkVerify(30, b) }

func benchmarkVerify(bnum int, b *testing.B) {
	s := SetupTest(bnum, 0, 1000)
	defer FinishTest(s)
	pk := s.B[0].pki.PK

	// Need a copy of these because CreateEncryptedTransaction will
	// send it to the ledger, which will cause each bank to process
	// it, updating intermediate datastructures and no longer making
	// it valid.
	commsCache := make([]zksigma.ECPoint, bnum)
	rtokenCache := make([]zksigma.ECPoint, bnum)
	for i := 0; i < bnum; i++ {
		commsCache[i] = zksigma.ECPoint{big.NewInt(0).Set(s.B[0].CommsCache[i].X), big.NewInt(0).Set(s.B[0].CommsCache[i].Y)}
		rtokenCache[i] = zksigma.ECPoint{big.NewInt(0).Set(s.B[0].RTokenCache[i].X), big.NewInt(0).Set(s.B[0].RTokenCache[i].Y)}
	}
	etx := s.B[0].CreateEncryptedTransaction(1, big.NewInt(1))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := etx.Verify(pk, commsCache, rtokenCache, "")
		if !v {
			panic("did not verify")
		}
	}
	b.StopTimer()
}

func BenchmarkCreateTxnTwoBanks(b *testing.B)      { benchmarkCreateTxn(2, b) }
func BenchmarkCreateTxnFourBanks(b *testing.B)     { benchmarkCreateTxn(4, b) }
func BenchmarkCreateTxnSixBanks(b *testing.B)      { benchmarkCreateTxn(6, b) }
func BenchmarkCreateTxnEightBanks(b *testing.B)    { benchmarkCreateTxn(8, b) }
func BenchmarkCreateTxnTenBanks(b *testing.B)      { benchmarkCreateTxn(10, b) }
func BenchmarkCreateTxnTwelveBanks(b *testing.B)   { benchmarkCreateTxn(12, b) }
func BenchmarkCreateTxnFourteenBanks(b *testing.B) { benchmarkCreateTxn(14, b) }
func BenchmarkCreateTxnSixteenBanks(b *testing.B)  { benchmarkCreateTxn(16, b) }
func BenchmarkCreateTxnEighteenBanks(b *testing.B) { benchmarkCreateTxn(18, b) }
func BenchmarkCreateTxnTwentyBanks(b *testing.B)   { benchmarkCreateTxn(20, b) }

func benchmarkCreateTxn(bnum int, b *testing.B) {
	s := SetupTest(bnum, 0, 1000)
	defer FinishTest(s)
	StopWhen(s, b.N+bnum)
	s.B[0].Issue(big.NewInt(int64(2*b.N)), nil)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.B[0].CreateEncryptedTransaction(1, big.NewInt(1))
	}
	Wait(s)
	b.StopTimer()
}

func xxTestMemUsage(t *testing.T) {
	bnum := 10
	pki := &PKI{}
	pki.MakeTest(bnum)
	banks := SetupLocalBanks(bnum, nil, pki)
	time.Sleep(20 * time.Millisecond)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	for j := 0; j < 100; j++ {
		etx := &EncryptedTransaction{}
		if *rpOutside {
			generateRangeProofs(bnum, etx, 1, 0, big.NewInt(1))
		}
		banks[0].createLocal(etx, 1, big.NewInt(1))
	}
	var mem2 runtime.MemStats
	runtime.ReadMemStats(&mem2)
	fmt.Printf("%v banks: alloc %v, total alloc %v, heap alloc %v, heap sys %v\n", bnum, mem2.Alloc-mem.Alloc, mem2.TotalAlloc-mem.TotalAlloc, mem2.HeapAlloc-mem.HeapAlloc, mem2.HeapSys-mem.HeapSys)
}

func BenchmarkCreateLocalTxnTwoBanks(b *testing.B)        { benchmarkCreateLocalTxn(2, b) }
func BenchmarkCreateLocalTxnFourBanks(b *testing.B)       { benchmarkCreateLocalTxn(4, b) }
func BenchmarkCreateLocalTxnSixBanks(b *testing.B)        { benchmarkCreateLocalTxn(6, b) }
func BenchmarkCreateLocalTxnEightBanks(b *testing.B)      { benchmarkCreateLocalTxn(8, b) }
func BenchmarkCreateLocalTxnTenBanks(b *testing.B)        { benchmarkCreateLocalTxn(10, b) }
func BenchmarkCreateLocalTxnTwelveBanks(b *testing.B)     { benchmarkCreateLocalTxn(12, b) }
func BenchmarkCreateLocalTxnFourteenBanks(b *testing.B)   { benchmarkCreateLocalTxn(14, b) }
func BenchmarkCreateLocalTxnSixteenBanks(b *testing.B)    { benchmarkCreateLocalTxn(16, b) }
func BenchmarkCreateLocalTxnEighteenBanks(b *testing.B)   { benchmarkCreateLocalTxn(18, b) }
func BenchmarkCreateLocalTxnTwentyBanks(b *testing.B)     { benchmarkCreateLocalTxn(20, b) }
func BenchmarkCreateLocalTxnTwentyFourBanks(b *testing.B) { benchmarkCreateLocalTxn(24, b) }
func BenchmarkCreateLocalTxnThirtyBanks(b *testing.B)     { benchmarkCreateLocalTxn(30, b) }

func benchmarkCreateLocalTxn(bnum int, b *testing.B) {
	pki := &PKI{}
	pki.MakeTest(bnum)
	banks := SetupLocalBanks(bnum, nil, pki)
	banks[0].ValueCache.Add(banks[0].ValueCache, big.NewInt(int64(2*b.N)))
	b.ResetTimer()
	etx := &EncryptedTransaction{}
	for i := 0; i < b.N; i++ {
		if *rpOutside {
			generateRangeProofs(bnum, etx, 1, 0, big.NewInt(1))
		}
		banks[0].createLocal(etx, 1, big.NewInt(1))
	}
}

func BenchmarkUpdateCommCache(b *testing.B) {
	value := new(big.Int).SetInt64(50)
	comm, _, _ := zksigma.PedCommit(value)
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		comm = comm.Add(comm)
	}
}
