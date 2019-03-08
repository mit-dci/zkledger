package zkledger

import (
	"fmt"
	"log"
	"math/big"
	"net"
	"net/rpc"
	"sync"

	"github.com/mit-dci/zksigma"
)

type Auditor struct {
	num          int
	local_ledger *LocalLedger
	receivedTxns chan *EncryptedTransaction
	mu           *sync.Mutex
	lastSeen     int
	Done         chan bool
	banks        []BankClient
	pki          *PKI
	CommsCache   []zksigma.ECPoint
	RTokenCache  []zksigma.ECPoint
	Setup        chan struct{}
}

func MakeAuditor(num int, pki *PKI) *Auditor {
	a := &Auditor{
		num:          num,
		local_ledger: MakeLocalLedger(),
		receivedTxns: make(chan *EncryptedTransaction, TXN_BUFFER),
		mu:           new(sync.Mutex),
		lastSeen:     -1,
		Done:         make(chan bool),
		pki:          pki,
		Setup:        make(chan struct{}),
	}
	a.CommsCache = make([]zksigma.ECPoint, a.num)
	a.RTokenCache = make([]zksigma.ECPoint, a.num)
	for i := 0; i < a.num; i++ {
		a.CommsCache[i] = zksigma.Zero
		a.RTokenCache[i] = zksigma.Zero
	}
	go a.start()
	return a
}

func (a *Auditor) Go(c APLClientConfig, _ *struct{}) error {
	go a.register(c.Hostname, c.BasePort, c.BankHostnames)
	a.listen(c.Hostname, c.BasePort)
	return nil
}

func (a *Auditor) listen(hostname string, basePort int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", basePort+a.num+2))
	if err != nil {
		log.Fatalf("[A] Could not listen %v\n", err)
	}
	err = rpc.Register(a)
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}
		go rpc.ServeConn(conn)
	}
}

func (a *Auditor) register(hostname string, baseport int, bankHostnames []string) {
	var wg sync.WaitGroup
	a.banks = make([]BankClient, a.num)
	for i := 0; i < a.num; i++ {
		wg.Add(1)
		go func(i int) {
			x := MakeRemoteBankClient()
			x.connect(bankHostnames[i], baseport+i+1)
			a.banks[i] = x
			wg.Done()
		}(i)
	}
	wg.Wait()
	Dprintf("[A] Registered with banks\n")
	close(a.Setup)
}

func (a *Auditor) start() {
	<-a.Setup
	Dprintf("[A] Starting audit loop...\n")
	var pks []zksigma.ECPoint
	for {
		select {
		case etx := <-a.receivedTxns:
			Dprintf("[A][%v]  Received txn...\n", etx.Index)
			// Verify
			if pks == nil {
				pks = make([]zksigma.ECPoint, a.num+1) // all the banks and the issuer
				for i := 0; i < a.num+1; i++ {
					pks[i] = a.pki.Get(i)
				}
			}
			if *emptyTxn {
				continue
			}
			a.mu.Lock()
			if !etx.Verify(pks, a.CommsCache, a.RTokenCache, "A") {
				log.Fatalf("[A][%v] Bad transaction!\n", etx.Index)
			}
			Dprintf("[A][%v]   Verified txn...\n", etx.Index)
			lastSeen := a.lastSeen
			a.mu.Unlock()
			if etx.Index < lastSeen {
				log.Fatalf("[A] lastSeen %v out of whack with received transactions %v\n", lastSeen, etx.Index)
			} else if etx.Index == lastSeen {
				log.Fatalf("[A] lastSeen %v out of whack with received transactions %v\n", lastSeen, etx.Index)
			} else if etx.Index == lastSeen+1 {
				a.mu.Lock()
				a.lastSeen = a.lastSeen + 1
				etx.reduce()
				a.local_ledger.add(etx)
				if etx.Type == Transfer {
					for i := 0; i < len(etx.Entries); i++ {
						//Dprintf("[A]   Adding RToken %v...\n", etx.Entries[i].RToken)
						a.RTokenCache[i] = ZKLedgerCurve.Add(a.RTokenCache[i], etx.Entries[i].RToken)
						a.CommsCache[i] = ZKLedgerCurve.Add(a.CommsCache[i], etx.Entries[i].Comm)
					}
				} else if etx.Type == Issuance || etx.Type == Withdrawal {
					// Only one bank for now
					en := &etx.Entries[etx.Sender]
					gval := ZKLedgerCurve.Mult(ZKLedgerCurve.G, en.V)
					a.CommsCache[etx.Sender] = ZKLedgerCurve.Add(a.CommsCache[etx.Sender], gval)
				}
				Dprintf("[A][%v] Processed txn\n", etx.Index)
				a.mu.Unlock()
			} else {
				Dprintf("[A][%v] Received txn out of order, expected %v\n", etx.Index, a.lastSeen)
				a.receivedTxns <- etx
			}
		case <-a.Done:
			Dprintf("[A] Shutting down audit loop...\n")
			close(a.receivedTxns)
			return
		}
	}
}

func (a *Auditor) Stop(_ *struct{}, _ *struct{}) error {
	a.Done <- true
	return nil
}

func (a *Auditor) Notify(etx *EncryptedTransaction, _ *struct{}) error {
	Dprintf("[A][%v] Notified of txn\n", etx.Index)
	a.receivedTxns <- etx
	return nil
}

// Compute # of asset for a given bank according to the ledger.
func (a *Auditor) computeSum(bank_i int) (*big.Int, bool) {
	Dprintf("[A] Auditing bank %v \n", bank_i)
	var rep AuditRep
	a.banks[bank_i].Audit(&struct{}{}, &rep)
	comms := zksigma.Zero
	rtokens := zksigma.Zero
	a.mu.Lock()
	if *useCache {
		comms = a.CommsCache[bank_i]
		rtokens = a.RTokenCache[bank_i]
	} else {
		for i := 0; i < len(a.local_ledger.Transactions); i++ {
			etx := &a.local_ledger.Transactions[i]
			if etx.Type == Transfer {
				comms = ZKLedgerCurve.Add(comms, etx.Entries[bank_i].Comm)
				rtokens = ZKLedgerCurve.Add(rtokens, etx.Entries[bank_i].RToken)
			} else if (etx.Type == Issuance || etx.Type == Withdrawal) && etx.Sender == bank_i {
				gval := ZKLedgerCurve.Mult(ZKLedgerCurve.G, etx.Entries[etx.Sender].V)
				comms = ZKLedgerCurve.Add(comms, gval)
			}
		}
	}
	a.mu.Unlock()
	gv := ZKLedgerCurve.Neg(ZKLedgerCurve.Mult(ZKLedgerCurve.G, rep.Sum)) // 1 / g^\sum{v_i}
	T := ZKLedgerCurve.Add(comms, gv)
	// TODO: Error handling
	verifies, _ := rep.Eproof.Verify(ZKLedgerCurve, T, rtokens, ZKLedgerCurve.H, a.pki.Get(bank_i))
	if !verifies {
		Dprintf("[A] Bank %v proof didn't verify! Their total: %v\n", bank_i, rep.Sum)
		Dprintf("     My \\sum{rtks_i}: %v\n", rtokens)
		Dprintf("    My \\sum{comms_i}: %v\n", comms)
		Dprintf("            gv: %v\n", gv)
		Dprintf("             T: %v\n", T)
	}
	return rep.Sum, verifies
}

// Should hold a.mu.  OK to call in parallel for different banks.
func (a *Auditor) sumOneBank(wg *sync.WaitGroup, bank_i int, totals []*big.Int, cache bool) {
	var rep AuditRep
	a.banks[bank_i].Audit(&struct{}{}, &rep)
	comms := zksigma.Zero
	rtokens := zksigma.Zero
	if *useCache && cache {
		comms = a.CommsCache[bank_i]
		rtokens = a.RTokenCache[bank_i]
	} else {
		for i := 0; i < len(a.local_ledger.Transactions); i++ {
			etx := &a.local_ledger.Transactions[i]
			if etx.Type == Transfer {
				comms = ZKLedgerCurve.Add(comms, etx.Entries[bank_i].Comm)
				rtokens = ZKLedgerCurve.Add(rtokens, etx.Entries[bank_i].RToken)
			} else if (etx.Type == Issuance || etx.Type == Withdrawal) && etx.Sender == bank_i {
				gval := ZKLedgerCurve.Mult(ZKLedgerCurve.G, etx.Entries[etx.Sender].V)
				comms = ZKLedgerCurve.Add(comms, gval)
			}
		}
	}
	gv := ZKLedgerCurve.Neg(ZKLedgerCurve.Mult(ZKLedgerCurve.G, rep.Sum)) // 1 / g^\sum{v_i}
	T := ZKLedgerCurve.Add(comms, gv)
	// TODO: Error handling
	verifies, _ := rep.Eproof.Verify(ZKLedgerCurve, T, rtokens, ZKLedgerCurve.H, a.pki.Get(bank_i))
	if !verifies {
		Dprintf("[A] Bank %v proof didn't verify! Their total: %v\n", bank_i, rep.Sum)
		Dprintf("     My \\sum{rtks_i}: %v\n", rtokens)
		Dprintf("    My \\sum{comms_i}: %v\n", comms)
		Dprintf("            gv: %v\n", gv)
		Dprintf("             T: %v\n", T)
	}
	totals[bank_i] = rep.Sum
	wg.Done()
}

func (a *Auditor) Herfindahl(cache bool, _ *struct{}) (*big.Rat, error) {
	<-a.Setup
	totals := make([]*big.Int, a.num)
	total := big.NewInt(0)
	concentrations := make([]*big.Rat, a.num)
	var wg sync.WaitGroup
	a.mu.Lock()
	defer a.mu.Unlock()
	wg.Add(a.num)
	for i := 0; i < a.num; i++ {
		go a.sumOneBank(&wg, i, totals, cache)
		concentrations[i] = new(big.Rat)
	}
	wg.Wait()
	for i := 0; i < a.num; i++ {
		total.Add(total, totals[i])
	}
	Dprintf("[A] Herfindahl: %v totals, %v total\n", totals, total)
	hIndex := big.NewRat(0, 1)
	for i := 0; i < a.num; i++ {
		marketShare := new(big.Rat).Quo(new(big.Rat).SetInt(totals[i]), new(big.Rat).SetInt(total))

		hIndex.Add(hIndex, new(big.Rat).Mul(marketShare, marketShare)) // add the sum of squares of the market share
	}
	return hIndex, nil
}

// Compute # of asset for a given bank according to unencrypted test
// values in the ledger.  ONLY TO BE USED FOR TESTING.
func (a *Auditor) computeClearSum(bank_i int) *big.Int {
	total := big.NewInt(0)
	for i := 0; i < len(a.local_ledger.Transactions); i++ {
		total.Add(total, a.local_ledger.Transactions[i].Entries[bank_i].V)
	}
	return total
}

// Compute # total outstanding of an asset.
func (a *Auditor) computeOutstanding() *big.Int {
	total := big.NewInt(0)
	for i := 0; i < a.num; i++ {
		v, err := a.computeSum(i)
		if !err {
			log.Fatalf("Commitments and rvals did not match for bank %v\n", i)
		}
		total.Add(total, v)
	}
	return total
}

func (a *Auditor) Audit(_ *struct{}, _ *struct{}) *big.Int {
	<-a.Setup
	Dprintf("[A] Auditing all banks \n")
	return a.computeOutstanding()
}

func (a *Auditor) GetNumTX(_ *struct{}, _ *struct{}) int {
	return len(a.local_ledger.Transactions)
}

// X Amount of some risky thing outstanding (outstanding sum)
// X Amount of some risky thing at one bank (sum)
// - Aggregate risk exposures (outstanding sum?)
// X Herfindahl concentration index
// - Aggregate leverage
// - Margin-to-equity ratios
// - Leverage ratios
// - Average correlations between *changes* in securities holdings
