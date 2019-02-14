package zkledger

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/rpc"
	"sync"
	"time"
)

const (
	TXN_BUFFER = 100
)

var useCache = flag.Bool("useCache", true, "Use cached sums when auditing")
var rpOutside = flag.Bool("rp", true, "Generate 0 Range Proofs outside of lock")
var waitAppend = flag.Bool("wa", true, "Whether or not to wait for the AppendTxn to return")
var emptyTxn = flag.Bool("et", false, "Send around empty txns and no verifying")

func SetupLocalBanks(n int, l LedgerClient, pki *PKI) []*Bank {
	allbanks := make([]*Bank, n)
	for i := 0; i < n; i++ {
		allbanks[i] = MakeBank(i, n, l, pki)
	}
	for i := 0; i < n; i++ {
		allbanks[i].banks = make([]BankClient, n)
		for j := 0; j < n; j++ {
			allbanks[i].banks[j] = allbanks[j]
		}
	}
	return allbanks
}

// All transactions I'm involved with
type Transaction struct {
	ts       time.Time
	index    int
	sender   int
	receiver int // For now, assume single sender and receiver
	value    *big.Int
	r        *big.Int
}

type Bank struct {
	id  int
	num int
	pki *PKI
	mu  *sync.Mutex

	// My copy of the global ledger.  This will have *all*
	// transactions in it, not just ones I was involved in.
	local_ledger *LocalLedger

	// Unencrypted versions of my sent and received transactions so I
	// can compute things for the auditor
	transactions map[int]*Transaction

	// Running total of the sum of the commitments for everyone in all
	// previous rows (this should be per asset)
	CommsCache []ECPoint

	// Running total of my assets (this should be per asset)
	ValueCache *big.Int

	// Running total of the sum of the rtokens for everyone in all
	// previous rows (this should be per asset)
	RTokenCache []ECPoint

	lastSeen     int
	receivedTxns chan *EncryptedTransaction

	Done   chan bool
	ledger LedgerClient
	banks  []BankClient
	issuer IssuerClient

	Inflight      map[int]chan struct{}
	Setup         chan struct{}
	When          int
	Waiter        chan struct{}
	StoreRequests map[int]*StoreArgs
}

func MakeBank(id int, num int, l LedgerClient, pki *PKI) *Bank {
	b := &Bank{
		id:            id,
		num:           num,
		pki:           pki,
		mu:            new(sync.Mutex),
		local_ledger:  MakeLocalLedger(),
		transactions:  make(map[int]*Transaction),
		ledger:        l,
		Done:          make(chan bool),
		CommsCache:    make([]ECPoint, num),
		lastSeen:      -1,
		receivedTxns:  make(chan *EncryptedTransaction, TXN_BUFFER),
		ValueCache:    big.NewInt(0), // TODO: Add initial assets to banks
		RTokenCache:   make([]ECPoint, num),
		Inflight:      make(map[int]chan struct{}),
		Setup:         make(chan struct{}),
		Waiter:        make(chan struct{}),
		StoreRequests: make(map[int]*StoreArgs),
	}
	c := make(chan struct{})
	b.Inflight[-1] = c
	close(c)

	for i := 0; i < num; i++ {
		b.CommsCache[i] = ECPoint{big.NewInt(0), big.NewInt(0)}
		b.RTokenCache[i] = ECPoint{big.NewInt(0), big.NewInt(0)}
	}
	go b.start()
	return b
}

func (b *Bank) log(str string, idx int, args ...interface{}) {
	x := fmt.Sprintf(str, args...)
	if idx > -1 {
		Dprintf("[%v][%v] %s", b.id, idx, x)
	} else {
		Dprintf("[%v] %s", b.id, x)
	}
}

func (b *Bank) listen(hostname string, basePort int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", (basePort)+(b.id)+1))
	if err != nil {
		log.Fatalf("[%v] Could not listen %v\n", b.id, err)
	}
	err = rpc.Register(b)
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

func (b *Bank) Go(c APLClientConfig, _ *struct{}) error {
	go b.register(c.Hostname, c.BasePort, c.BankHostnames, c.LedgerHostname)
	b.listen(c.Hostname, c.BasePort)
	return nil
}

func (b *Bank) register(hostname string, basePort int, bankHostnames []string, ledgerHostname string) {
	var wg sync.WaitGroup
	b.banks = make([]BankClient, b.num)
	for i := 0; i < b.num; i++ {
		if i == b.id {
			continue
		}
		wg.Add(1)
		go func(i int) {
			x := MakeRemoteBankClient()
			x.connect(bankHostnames[i], basePort+i+1)
			b.banks[i] = x
			wg.Done()
		}(i)
	}
	wg.Add(1)
	go func() {
		x := MakeRemoteLedgerClient()
		x.Connect(ledgerHostname, basePort)
		b.ledger = x
		wg.Done()
	}()
	wg.Wait()
	b.log("Registered with banks and ledger\n", -1)
	close(b.Setup)
}

func (b *Bank) start() {
	<-b.Setup
	Dprintf("[%v] Starting bank loop...\n", b.id)
	for {
		select {
		case etx := <-b.receivedTxns:
			b.log(" Received txn...\n", etx.Index)
			b.mu.Lock()
			lastSeen := b.lastSeen
			if etx.Index <= lastSeen {
				log.Fatalf("[%v][%v] lastSeen %v out of whack with received transaction\n",
					b.id, etx.Index, lastSeen)
				b.mu.Unlock()
			} else if etx.Index == lastSeen+1 {
				//b.log("  Received txn equal to lastSeen+1...\n", etx.Index)
				if !*emptyTxn {
					// I wonder: if this is *my* transaction, do I
					// need to verify it?  I don't think I do, but how
					// can I be sure it really is my transaction?
					// Could keep a hash of etx's I create a round and
					// verify that it is the same one I created.
					// Future work.
					start := time.Now()
					if !etx.Verify(b.pki.PK, b.CommsCache, b.RTokenCache, fmt.Sprintf("%d", b.id)) {
						log.Fatalf("[%v] Bad transaction!\n", b.id)
					}
					b.log("time txn verify %v\n", etx.Index, time.Since(start))
				}
				b.updateLocalData(etx)
				if b.When != 0 && etx.Index == b.When {
					b.log("  Closing waiter on txn %v...\n", etx.Index, etx.Index)
					close(b.Waiter)
				}
				b.mu.Unlock()
			} else {
				b.log("  Received txn out of order, expected %v\n", etx.Index, lastSeen+1)
				b.mu.Unlock()
				b.receivedTxns <- etx
			}
		case <-b.Done:
			Dprintf("[%v] Shutting down bank loop...%v left\n", b.id, len(b.receivedTxns))
			close(b.receivedTxns)
			return
		}
	}
}

func (b *Bank) Stop(_ *struct{}, _ *struct{}) error {
	b.Done <- true
	return nil
}

func (b *Bank) DumpLedger(_ *struct{}, _ *struct{}) error {
	b.local_ledger.DumpReadableLedger(nil, nil)
	b.local_ledger.DumpLedger(nil, nil)
	return nil
}

func (b *Bank) print_transactions() {
	if !*DEBUG {
		return
	}
	Dprintf("[%v]\t{", b.id)
	for _, tx := range b.transactions {
		Dprintf("%v:[%v->%v, %v, %v] ", tx.index, tx.sender, tx.receiver, tx.value, tx.r)
	}
	Dprintf("}\n")
	Dprintf("[%v]\t commscache: %v\trtokencache: %v\tvaluecache: %v\n", b.id, b.CommsCache[b.id], b.RTokenCache[b.id], b.ValueCache)
}

type StoreArgs struct {
	TS time.Time
	I  int
	C  ECPoint
	S  int
	Re int
	V  big.Int
	R  big.Int
}

// Store the cleartext data from a transaction someone is sending me,
// locally.  A malicious bank might not give me the correct cleartext
// data, in which case I would have to brute force the value.  Not
// implemented.
//
// I might get this *before* I process the encrypted transaction, in
// which case, my value cache will be out of sync with my other
// caches.  So I'm going to wait till I process this transaction to
// actually update my stores.  Save this in a map!
func (b *Bank) Store(req *StoreArgs, _ *struct{}) error {
	if !*emptyTxn {
		b.log("  .Saving %v value for %v from %v ...\n", req.I, req.V.Int64(), req.Re, req.S)
		b.StoreRequests[req.I] = req
		//return b.store_locally(req.TS, req.I, req.C, req.S, b.id, &req.V, &req.R)
	}
	return nil
}

// Add a transaction I've either sent or received to my store.  Should hold mu
func (b *Bank) store_locally(ts time.Time, index int, comm ECPoint, sender int, receiver int, value *big.Int, r *big.Int) error {
	if *emptyTxn {
		return nil
	}
	b.log("   .Storing value %v from %v locally. ledger size: %v...\n", index, value, sender, len(b.transactions))
	tx := Transaction{
		ts:       ts,
		index:    index,
		receiver: receiver,
		value:    value,
		sender:   sender,
		r:        r, // For debug purposes only.
	}
	b.transactions[index] = &tx
	b.ValueCache.Add(b.ValueCache, value)
	return nil
}

// Wait for the previous transaction to be processed.
func (b *Bank) wait(idx int) {
	b.mu.Lock()
	c, ok := b.Inflight[idx-1]
	if !ok {
		// I'm the first person to need it.
		b.log("No one set up channel for waiters on txn(%v)\n", idx, idx-1)
		c = make(chan struct{})
		b.Inflight[idx-1] = c
	}
	b.mu.Unlock()
	start := time.Now()
	<-c
	b.log("time c wait %v\n", idx, time.Since(start))
}

func (b *Bank) Issue(value *big.Int, _ *struct{}) *EncryptedTransaction {
	<-b.Setup
	b.log("Starting ISSUE\n", -1)
	etx := &EncryptedTransaction{}
	// Might block, waiting for previous transaction to complete at
	// the ledger.
	start := time.Now()
	b.ledger.StartTxn(b.id, &etx.Index)
	b.log("time waiting to StartTxn %v\n", etx.Index, time.Since(start))
	// Just because it completed at the ledger does not mean it was
	// processed.
	b.wait(etx.Index)
	start = time.Now()
	etx.Type = Issuance
	etx.Sender = b.id
	etx.Entries = make([]Entry, b.num)
	etx.Entries[b.id].V = value
	etx.TS = time.Now()
	g := GSPFS{curve: EC.C, ExponentPrime: EC.N, Generator: EC.H}
	// TODO: Use a proof of the issuer
	proof := g.Prove(b.pki.Get(len(b.banks)), b.pki.GetSK(len(b.banks))) // use the key of the issuer in order to create a new issuance
	etx.Entries[b.id].SKProof = proof
	b.mu.Lock()
	b.store_locally(etx.TS, etx.Index, etx.Entries[b.id].Comm, b.id, -1, value, nil)
	b.mu.Unlock()
	b.log("time Local %v\n", etx.Index, time.Since(start))
	// Submit to global ledger
	b.log("Appending to ledger txn from b%v issuance amt %v\n", etx.Index, b.id, value)
	start = time.Now()
	b.ledger.AppendTxn(etx, nil)
	b.log("time AppendTxn %v\n", etx.Index, time.Since(start))
	b.log("Appended to ledger txn from b%v issuance amt %v\n", etx.Index, b.id, value)
	return etx
}

func (b *Bank) Withdraw(value *big.Int, _ *struct{}) *EncryptedTransaction {
	<-b.Setup
	etx := &EncryptedTransaction{}
	// Might block, waiting for previous transaction to complete at
	// the ledger.
	start := time.Now()
	b.ledger.StartTxn(b.id, &etx.Index)
	b.log("time waiting to StartTxn %v\n", etx.Index, time.Since(start))
	// Just because it completed at the ledger does not mean it was
	// processed.
	b.wait(etx.Index)
	b.log("Ready to start withdrawal\n", etx.Index)
	start = time.Now()
	etx.Type = Withdrawal
	etx.Sender = b.id
	etx.Entries = make([]Entry, b.num)
	etx.Entries[b.id].V = value
	etx.TS = time.Now()
	g := GSPFS{curve: EC.C, ExponentPrime: EC.N, Generator: EC.H}
	proof := g.Prove(b.pki.Get(b.id), b.pki.GetSK(b.id))
	etx.Entries[b.id].SKProof = proof
	b.mu.Lock()
	b.store_locally(etx.TS, etx.Index, etx.Entries[b.id].Comm, b.id, -1, value, nil)
	b.mu.Unlock()
	b.log("time Local %v\n", etx.Index, time.Since(start))
	// Submit to global ledger
	b.log("Appending to ledger txn from b%v withdrawal amt %v\n", etx.Index, b.id, value)
	start = time.Now()
	b.ledger.AppendTxn(etx, nil)
	b.log("time AppendTxn %v\n", etx.Index, time.Since(start))
	b.log("Appended to ledger txn from b%v withdrawal amt %v\n", etx.Index, b.id, value)
	return etx
}

func generateRangeProofs(num int, etx *EncryptedTransaction, bank_j int, id int, value *big.Int) {
	etx.Entries = make([]Entry, num)
	for i := 0; i < num; i++ {
		if i == id {
			continue
		} else if i == bank_j {
			etx.Entries[i].RP, etx.Entries[i].BAuxR = RangeProverProve(value)
		} else {
			etx.Entries[i].RP, etx.Entries[i].BAuxR = RangeProverProve(big.NewInt(0))
		}
	}
}

// Create a transaction for sending to another bank
func (b *Bank) CreateEncryptedTransaction(bank_j int, value *big.Int) *EncryptedTransaction {
	<-b.Setup
	if bank_j == b.id {
		log.Fatalf("[%v] Sending a transaction to myself (not supported)\n", b.id)
	}
	etx := &EncryptedTransaction{}

	startx := time.Now()
	start := time.Now()

	if *rpOutside && !*emptyTxn {
		// Pre-generate proofs
		generateRangeProofs(b.num, etx, bank_j, b.id, value)
		b.log("time to make %v RPs %v\n", -1, b.num-1, time.Since(start))
	}

	// Might block, waiting for previous transaction to complete at
	// the ledger.
	start = time.Now()
	b.ledger.StartTxn(b.id, &etx.Index)
	b.log("time waiting to StartTxn %v\n", etx.Index, time.Since(start))
	start2 := time.Now()

	// Just because it completed at the ledger does not mean I
	// processed the previous transaction.  When this returns, it
	// means I've updated all of my local data caches to reflect
	// transaction etx.Index-1, so I'm ready to produce this one.
	b.wait(etx.Index)

	start = time.Now()

	var theirR *big.Int
	if !*emptyTxn {
		theirR = b.createLocal(etx, bank_j, value)
		b.log("time CreateLocal %v\n", etx.Index, time.Since(start))
	}
	_ = theirR

	var args *StoreArgs
	if !*emptyTxn {
		// Send to bank_j for storing it locally.  Have to do it here
		// because before the ledger lock I don't know the index;
		// after, it might be too late and the receiver will process
		// the txn not even knowing he got funds.
		args = &StoreArgs{TS: etx.TS, I: etx.Index, C: etx.Entries[bank_j].Comm, S: b.id, Re: bank_j, V: *value, R: *theirR}
	}
	start = time.Now()
	b.banks[bank_j].Store(args, nil)
	b.log("time Store %v\n", etx.Index, time.Since(start))

	// Submit to global ledger
	b.log("Appending to ledger txn from b%v to b%v amt %v\n", etx.Index, b.id, bank_j, value)
	start = time.Now()
	if *waitAppend {
		b.ledger.AppendTxn(etx, nil)
		b.log("time AppendTxn call %v\n", etx.Index, time.Since(start))
	} else {
		go func(start time.Time) {
			b.ledger.AppendTxn(etx, nil)
			b.log("time AppendTxn call (didn't wait) %v\n", etx.Index, time.Since(start))
		}(start)
	}
	b.log("time with Ledger lock %v\n", etx.Index, time.Since(start2))
	b.log("time total CreateEncryptedTxn %v\n", etx.Index, time.Since(startx))

	return etx
}

// All-local create transaction function
func (b *Bank) createLocal(etx *EncryptedTransaction, bank_j int, value *big.Int) *big.Int {
	var myR *big.Int
	var theirR *big.Int
	var tmpR *big.Int
	var commaux ECPoint
	var rp *big.Int
	var rtoken ECPoint
	var baux ECPoint
	vn := new(big.Int).Neg(value)
	totalR := big.NewInt(0)
	//gsp := GSPFS{curve: EC.C, ExponentPrime: EC.N, Generator: EC.H}
	pc := ECPedersen{EC.C, EC.G, EC.H}
	etx.Sender = b.id     // testing
	etx.Receiver = bank_j // testing

	// Sometimes I create this before createLocal, for example when
	// pre-generating range proofs.  Sometimes not (current tests)
	if len(etx.Entries) == 0 {
		etx.Entries = make([]Entry, b.num)
	}
	etx.TS = time.Now()
	for i := 0; i < b.num; i++ {
		etx.Entries[i].Bank = i
		if i == bank_j {
			// Commit to value
			// we want all commitments to add up to identity of group, so we choose
			// the last randomness to be N-sumSoFar
			if i == b.num-1 {
				theirR = new(big.Int).Sub(EC.N, totalR)
				theirR.Mod(theirR, EC.N)
				etx.Entries[i].Comm = pc.CommitWithR(value, theirR)
				//fmt.Println("Last entry in TX", b.num)
			} else {
				etx.Entries[i].Comm, theirR = pc.Commit(value)
			}

			etx.Entries[i].V = value  // testing
			etx.Entries[i].R = theirR // testing
			tmpR = theirR
			rtoken = EC.CommitR(b.pki.Get(i), tmpR)

			// Range Proof to get randomness value to use
			if !*rpOutside {
				etx.Entries[i].RP, rp = RangeProverProve(value)
			} else {
				// Otherwise, Range Proof done before
				rp = etx.Entries[i].BAuxR
			}
			// cm_{aux,i} ~ cm
			commaux = pc.CommitWithR(value, rp)
			etx.Entries[i].CommAux = commaux
			baux = EC.CommitR(b.pki.Get(i), rp)
			rpmr := new(big.Int).Sub(rp, theirR)
			rpmr.Mod(rpmr, EC.N)

			// items for simulated proof
			b.mu.Lock()
			SA := b.CommsCache[i].Add(etx.Entries[i].Comm)
			SB := b.RTokenCache[i].Add(rtoken)
			b.mu.Unlock()
			Base1 := commaux.Add(SA.Neg()) // Base1 = CommAux - (\Sum_{i=0}^{n-1} CM_i + CM_n)
			Result1 := baux.Add(SB.Neg())  // Result1 = Baux - SB
			Result2 := commaux.Add(etx.Entries[i].Comm.Neg())

			etx.Entries[i].Assets = ProveDisjunctive(Base1, Result1, EC.H, Result2, rpmr, 1)
			etx.Entries[i].CommConsistency = ProveConsistency(etx.Entries[i].Comm, rtoken, b.pki.Get(bank_j), value, tmpR)
			etx.Entries[i].AuxConsistency = ProveConsistency(commaux, baux, b.pki.Get(bank_j), value, rp)
		} else if i == b.id {
			// Commit to negative value
			if i == b.num-1 {
				myR = new(big.Int).Sub(EC.N, totalR)
				myR.Mod(myR, EC.N)
				etx.Entries[i].Comm = pc.CommitWithR(vn, myR)

				//fmt.Println("Last entry in TX", b.num)
			} else {
				etx.Entries[i].Comm, myR = pc.Commit(vn)
			}
			etx.Entries[i].V = vn  // testing
			etx.Entries[i].R = myR // testing
			tmpR = myR
			rtoken = EC.CommitR(b.pki.Get(i), tmpR)
			b.mu.Lock()
			sum := new(big.Int).Add(vn, b.ValueCache)
			b.mu.Unlock()
			etx.Entries[i].RP, rp = RangeProverProve(sum)

			baux = EC.CommitR(b.pki.Get(i), rp)
			b.mu.Lock()
			// I shouldn't even be here unless the local data
			// structures have been updated from the n-1th
			// transaction, because I should have been stuck in the wait()

			SA := b.CommsCache[i].Add(etx.Entries[i].Comm) // SA = n-1 sum + curSum
			SB := b.RTokenCache[i].Add(rtoken)             //SB = n-1 sum + current rtoken
			b.mu.Unlock()

			commaux = pc.CommitWithR(sum, rp)
			etx.Entries[i].CommAux = commaux
			Base1 := commaux.Add(SA.Neg())
			Result1 := baux.Add(SB.Neg()) // Result1 = commaux - (sum of entries)
			Result2 := commaux.Add(etx.Entries[i].Comm.Neg())

			etx.Entries[i].Assets = ProveDisjunctive(Base1, Result1, EC.H, Result2, b.pki.GetSK(b.id), 0)
			etx.Entries[i].CommConsistency = ProveConsistency(etx.Entries[i].Comm, rtoken, b.pki.Get(i), vn, tmpR)
			etx.Entries[i].AuxConsistency = ProveConsistency(commaux, baux, b.pki.Get(i), sum, rp)
		} else {
			// Commit to 0
			if i == b.num-1 {
				tmpR = new(big.Int).Sub(EC.N, totalR)
				tmpR.Mod(tmpR, EC.N)
				etx.Entries[i].Comm = pc.CommitWithR(big.NewInt(0), tmpR)
				//fmt.Println("Last entry in TX", b.num)
			} else {
				etx.Entries[i].Comm, tmpR = pc.Commit(big.NewInt(0))
			}

			etx.Entries[i].V = big.NewInt(0) // testing
			etx.Entries[i].R = tmpR          // testing

			if !*rpOutside {
				etx.Entries[i].RP, rp = RangeProverProve(big.NewInt(0))
			} else {
				// Otherwise, Range Proof done before
				rp = etx.Entries[i].BAuxR
			}
			if rp == nil {
				panic("rp is null")
			}
			// cm_{aux,i} ~ cm
			commaux = pc.CommitWithR(big.NewInt(0), rp)
			etx.Entries[i].CommAux = commaux
			rtoken = EC.CommitR(b.pki.Get(i), tmpR)
			baux = EC.CommitR(b.pki.Get(i), rp)
			rpmr := new(big.Int).Sub(rp, tmpR)
			rpmr.Mod(rpmr, EC.N)

			b.mu.Lock()
			SA := b.CommsCache[i].Add(etx.Entries[i].Comm)
			SB := b.RTokenCache[i].Add(rtoken)
			b.mu.Unlock()
			Base1 := commaux.Add(SA.Neg())
			Result1 := baux.Add(SB.Neg())
			Result2 := commaux.Add(etx.Entries[i].Comm.Neg())

			etx.Entries[i].Assets = ProveDisjunctive(Base1, Result1, EC.H, Result2, rpmr, 1)
			etx.Entries[i].CommConsistency = ProveConsistency(etx.Entries[i].Comm, rtoken, b.pki.Get(i), big.NewInt(0), tmpR)
			etx.Entries[i].AuxConsistency = ProveConsistency(commaux, baux, b.pki.Get(i), big.NewInt(0), rp)
		}
		totalR = totalR.Add(totalR, tmpR)
		etx.Entries[i].RToken = rtoken
		etx.Entries[i].BAux = baux
	}

	// Add to my own local store.  At the moment, I expect appending
	// to the global ledger won't fail, and it will have the index I
	// expect, so I go ahead and do this now.

	var args *StoreArgs
	if !*emptyTxn {
		// Put in map to eventually store locally
		args = &StoreArgs{TS: etx.TS, I: etx.Index, C: etx.Entries[b.id].Comm, S: b.id, Re: bank_j, V: *vn, R: *myR}
	}
	b.Store(args, nil)
	return theirR
}

// The ledger is broadcasting a new transaction (it could be one of
// mine, but if so I should have stored it locally already)
func (b *Bank) Notify(etx *EncryptedTransaction, _ *struct{}) error {
	//b.log("Notified of txn\n", etx.Index)
	b.receivedTxns <- etx
	return nil
}

// Update local copy of ledger and commitment caches, and cleartext
// data structures for a transaction that has been confirmed on the
// ledger.  Note that if I created the transaction I might have
// updated them earlier.
//
// When done, wake up someone who might be waiting to create the next
// transaction.
//
// Should hold mu.
func (b *Bank) updateLocalData(etx *EncryptedTransaction) {
	b.log("   Processing txn and adding it to local ledger...\n", etx.Index)
	if !*emptyTxn {
		etx.reduce()
		b.local_ledger.add(etx)
		if etx.Type == Transfer {
			for i := 0; i < b.num; i++ {
				b.RTokenCache[i] = b.RTokenCache[i].Add(etx.Entries[i].RToken)
				b.CommsCache[i] = EC.Add(b.CommsCache[i], etx.Entries[i].Comm)
			}
			req, ok := b.StoreRequests[etx.Index]
			if !ok {
				// No saved store request
			} else {
				b.store_locally(req.TS, req.I, req.C, req.S, req.Re, &req.V, &req.R)
			}
		} else if etx.Type == Issuance || etx.Type == Withdrawal {
			// Only one bank
			en := &etx.Entries[etx.Sender]
			gval := EC.G.Mult(en.V)
			b.CommsCache[etx.Sender] = EC.Add(b.CommsCache[etx.Sender], gval)
		}
	}
	// Processed transaction etx.Index, signal whoever might be waiting for it.
	c, ok := b.Inflight[etx.Index]
	if !ok {
		// This might happen because no one at this bank is waiting
		// for etx.Index, cause it's not making more transactions.
		// Totally OK.  I didn't know this was coming!
		c = make(chan struct{})
		b.Inflight[etx.Index] = c
	}
	close(c)
	// Inform the next transaction who might be waiting for me later.
	_, ok = b.Inflight[etx.Index+1]
	if !ok {
		b.log("    Making channel for next waiter (on %v)\n", etx.Index, etx.Index+1)
		b.Inflight[etx.Index+1] = make(chan struct{})
	} else {
		b.log("    Someone already made a channel for next waiter (on %v)\n", etx.Index, etx.Index+1)
	}
	b.lastSeen = b.lastSeen + 1
	//	b.log("Processed txn\n", etx.Index)
	// Done processing transaction etx.Index
}

type AuditRep struct {
	Sum    *big.Int
	Eproof EquivProof
}

func (b *Bank) Audit(a *struct{}, rep *AuditRep) error {
	<-b.Setup
	rep.Sum, rep.Eproof = b.answerSum()
	return nil
}

type ComplexReq struct {
}

type ComplexRep struct {
	Recommitments []ECPoint
}

func (b *Bank) ComplexAudit(req *ComplexReq, rep *ComplexRep) error {
	<-b.Setup
	for i := 0; i < len(b.local_ledger.Transactions); i++ {
		etx := &b.local_ledger.Transactions[i]
		tx, ok := b.transactions[etx.Index]
		_ = tx
		if !ok {
			// Not my transaction
			continue
		}
		if etx.Type == Transfer {
		} else if (etx.Type == Issuance || etx.Type == Withdrawal) && etx.Sender == b.id {
		}
	}
	return nil
}

func (b *Bank) answerSum() (*big.Int, EquivProof) {
	b.mu.Lock()
	// return total quantity of asset, plus proof of knowledge
	total_comms := EC.Zero()          // Will be g^\sum{v_i}*h^\sum{r_i}
	total_rtoken := EC.Zero()         // Will be h^\sum{r_i}^sk
	total_clear := b.answerClearSum() // \sum{v_i}
	if *useCache {
		total_comms = b.CommsCache[b.id]
		total_rtoken = b.RTokenCache[b.id]
	} else {
		for i := 0; i < len(b.local_ledger.Transactions); i++ {
			etx := &b.local_ledger.Transactions[i]
			if etx.Type == Transfer {
				total_comms = EC.Add(total_comms, etx.Entries[b.id].Comm)
				total_rtoken = EC.Add(total_rtoken, etx.Entries[b.id].RToken)
			} else if (etx.Type == Issuance || etx.Type == Withdrawal) && etx.Sender == b.id {
				gval := EC.G.Mult(etx.Entries[etx.Sender].V)
				total_comms = EC.Add(total_comms, gval)
			}
		}
	}
	b.print_transactions()
	b.mu.Unlock()
	gv := EC.G.Mult(total_clear).Neg() // 1 / g^\sum{v_i}
	T := EC.Add(total_comms, gv)       // should be h^r
	Dprintf("[%v]  Audit:\n", b.id)
	Dprintf("[%v]       \\sum{v_i}: %v\n", b.id, total_clear)
	Dprintf("[%v]  1 /g^\\sum{v_i}: %v\n", b.id, gv)
	Dprintf("[%v]   \\sum{comms_i}: %v\n", b.id, total_comms)
	Dprintf("[%v]     \\sum{rtk_i}: %v\n", b.id, total_rtoken)
	Dprintf("[%v]              T: %v\n", b.id, T)
	eproof := ProveEquivalence(T, total_rtoken, EC.H, b.pki.Get(b.id), b.pki.GetSK(b.id))
	return total_clear, eproof
}

func (b *Bank) answerClearSum() *big.Int {
	total_clear := big.NewInt(0)
	if *useCache {
		total_clear = b.ValueCache
	} else {
		for _, v := range b.transactions {
			total_clear.Add(total_clear, v.value)
		}
	}
	return total_clear
}
