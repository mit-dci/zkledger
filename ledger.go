package apl

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/rpc"
	"sync"
	"time"
)

var parallelizeNotify = flag.Bool("pn", false, "Send notifications in parallel")
var waitNotify = flag.Bool("wn", true, "Hold lock on ledger until done notifying")

type LocalLedger struct {
	mu           *sync.Mutex
	Transactions []EncryptedTransaction
}

// Everyone has one of these.  Used to mirror global ledger.
func MakeLocalLedger() *LocalLedger {
	l := &LocalLedger{
		mu:           new(sync.Mutex),
		Transactions: make([]EncryptedTransaction, 0),
	}
	return l
}

func (l *LocalLedger) add(etx *EncryptedTransaction) int {
	etx.Index = len(l.Transactions)
	l.Transactions = append(l.Transactions, *etx)
	return etx.Index
}

func (l *LocalLedger) DumpLedger(_ *struct{}, _ *struct{}) error {
	var buf bytes.Buffer

	fmt.Println("> Dumping binary copy of ledger")
	enc := gob.NewEncoder(&buf)
	enc.Encode(l.Transactions)

	filename := "ledger_binary_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".byte"

	err := ioutil.WriteFile(filename, buf.Bytes(), 0666)
	check(err)
	return err
}

func (l *LocalLedger) LoadLedger(fn string, _ *struct{}) error {
	return nil
}

func (l *LocalLedger) DumpReadableLedger(_ *struct{}, _ *struct{}) error {
	var buf bytes.Buffer

	Dprintf("> Dumping readable copy of ledger\n")

	enc := json.NewEncoder(&buf)
	enc.Encode(l.Transactions)
	filename := "ledger_readable_" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".log"
	err := ioutil.WriteFile(filename, buf.Bytes(), 0666)
	check(err)
	return err
}

// Global, single server ledger
type Ledger struct {
	LocalLedger

	num     int
	Banks   []BankClient
	Auditor AuditorClient
	Setup   chan struct{}
	start   time.Time
}

func (l *Ledger) print_transactions() {
	Dprintf("L\t{")
	for i := 0; i < len(l.Transactions); i++ {
		tx := &l.Transactions[i]
		Dprintf("%v/%v:[%v] \n", i, tx.Index, tx.Entries)
	}
	Dprintf("}\n")
}

// Main ledger process
func MakeLedger(num int) *Ledger {
	l := &Ledger{
		LocalLedger: LocalLedger{
			mu:           new(sync.Mutex),
			Transactions: make([]EncryptedTransaction, 0),
		},
		num:   num,
		Setup: make(chan struct{}),
	}
	return l
}

func (l *Ledger) Go(c APLClientConfig, _ *struct{}) error {
	go l.register(c.Hostname, c.BasePort, c.BankHostnames, c.AuditorHostname)
	l.listen(c.Hostname, c.BasePort)
	return nil
}

func (l *Ledger) listen(hostname string, basePort int) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", basePort))
	if err != nil {
		log.Fatalf("[L] Could not listen\n")
	}
	err = rpc.Register(l)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println("[L] ERR accepting:", err)
			continue
		}
		Dprintf("[L] serving connection...\n")
		go rpc.ServeConn(conn)
	}
}

func (l *Ledger) register(hostname string, basePort int, bankHostname []string, auditorHostname string) {
	var wg sync.WaitGroup
	l.Banks = make([]BankClient, l.num)
	for i := 0; i < l.num; i++ {
		wg.Add(1)
		go func(i int) {
			x := MakeRemoteBankClient()
			x.connect(bankHostname[i], basePort+i+1)
			l.Banks[i] = x
			Dprintf("[L]    Connected to bank %v\n", i)
			wg.Done()
		}(i)
	}
	wg.Add(1)
	go func() { // TODO: Change this in order to support delayed auditor start or multiple auditors
		x := MakeRemoteAuditorClient()
		x.connect(auditorHostname, basePort+l.num+2)
		l.Auditor = x
		Dprintf("[L]    Connected to auditor\n")
		wg.Done()
	}()
	wg.Wait()
	close(l.Setup)
	Dprintf("[L]    Registered with banks and auditor\n")
}

// Bank reserving a spot in the ledger. Banks need to do this so they
// know their transaction insertion point, and can generate proofs
// accordingly with all the previous rows.
func (l *Ledger) StartTxn(bank_i int, idx *int) error {
	Dprintf("[L] ---Checking setup %v...\n", bank_i)
	<-l.Setup
	Dprintf("[L] ---Received start txn from %v...\n", bank_i)
	l.mu.Lock() // Hold lock until transaction is processed
	l.start = time.Now()
	*idx = len(l.Transactions)
	Dprintf("[L][%v] Assigning txn ID...\n", *idx)
	return nil
}

// Bank submitting a transaction to the global ledger. The ledger adds
// the transaction, and notifies everyone else so they can update
// their local ledgers.
func (l *Ledger) AppendTxn(etx *EncryptedTransaction, _ *struct{}) error {
	if *waitNotify {
		defer l.mu.Unlock()
	}
	Dprintf("[L][%v] Received txn ...\n", etx.Index)
	if len(l.Banks) == 0 {
		log.Panic("Need to set up the banks!")
	}
	if l.Auditor == nil {
		log.Panic("Need to set up the auditor!")
	}
	Dprintf("[L][%v] Processing new txn...\n", etx.Index)
	// TODO: verify, either here or in Append
	if etx.Index != len(l.Transactions) {
		log.Fatalf("[L]    Out of order receive; my index %v, etx: %v\n", len(l.Transactions), etx.Index)
	}
	l.add(etx)
	if !*waitNotify {
		Dprintf("[L][%v] time holding mu %v ...\n", etx.Index, time.Since(l.start))
		l.mu.Unlock()
	}
	if *parallelizeNotify {
		var wg sync.WaitGroup
		wg.Add(1 + l.num)
		go func() {
			if err := l.Auditor.Notify(etx, nil); err != nil {
				panic(err)
			}
			wg.Done()
		}()
		for i := 0; i < l.num; i++ {
			go func(i int) {
				if err := l.Banks[i].Notify(etx, nil); err != nil {
					panic(err)
				}
				wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		if err := l.Auditor.Notify(etx, nil); err != nil {
			panic(err)
		}
		for i := 0; i < l.num; i++ {
			if err := l.Banks[i].Notify(etx, nil); err != nil {
				panic(err)
			}
		}
	}
	Dprintf("[L][%v] time txn %v ...\n", etx.Index, time.Since(l.start))
	return nil
}
