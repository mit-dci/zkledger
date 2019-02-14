package zkledger

import "math/big"

type System struct {
	L *Ledger
	B []*Bank
	A *Auditor
}

func SetupTest(n int, ntx int, initialAmount int64) System {
	pki := &PKI{}
	pki.MakeTest(n)
	ledger := MakeLedger(n)
	auditor := MakeAuditor(n, pki)
	ledger.Auditor = auditor
	banks := SetupLocalBanks(n, ledger, pki)
	ledger.Banks = make([]BankClient, n)
	auditor.banks = make([]BankClient, n)
	for i := 0; i < n; i++ {
		ledger.Banks[i] = banks[i]
		auditor.banks[i] = banks[i]
		close(banks[i].Setup)
	}
	close(ledger.Setup)
	close(auditor.Setup)
	s := System{ledger, banks, auditor}

	// issue out funds to each bank
	for i := 0; i < n; i++ {
		v := big.NewInt(initialAmount)
		banks[i].Issue(v, nil) // issue money
	}
	for i := 0; i < ntx; i++ {
		sender := i % n
		receiver := (i + 1) % n
		banks[sender].CreateEncryptedTransaction(receiver, big.NewInt(100))
	}

	for i := 0; i < n; i++ {
		s.B[i].wait(ntx + n)
	}
	return s
}

func FinishTest(s System) {
	for i := 0; i < len(s.B); i++ {
		s.B[i].Stop(nil, nil)
	}
	s.A.Stop(nil, nil)
}

func StopWhen(s System, n int) {
	Dprintf("Setting wait to txn %v\n", n)
	for i := 0; i < len(s.B); i++ {
		s.B[i].When = n
	}
}

func Wait(s System) {
	for i := 0; i < len(s.B); i++ {
		<-s.B[i].Waiter
	}
}
