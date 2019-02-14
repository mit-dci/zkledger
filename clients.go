package zkledger

import (
	"fmt"
	"log"
	"math/big"
	"net/rpc"
	"time"
)

type APLClientConfig struct {
	Hostname        string
	BasePort        int
	BankHostnames   []string
	LedgerHostname  string
	AuditorHostname string
}

type BankClient interface {
	Audit(a *struct{}, rep *AuditRep) error
	Store(req *StoreArgs, _ *struct{}) error
	CreateEncryptedTransaction(bank_j int, value *big.Int) *EncryptedTransaction
	Notify(etx *EncryptedTransaction, _ *struct{}) error
}

type RemoteBankClient struct {
	client *rpc.Client
}

func MakeRemoteBankClient() *RemoteBankClient {
	bc := &RemoteBankClient{}
	return bc
}

func (bc *RemoteBankClient) connect(hostname string, port int) {
	for done := false; !done; {
		c, err := rpc.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
		if err == nil {
			bc.client = c
			done = true
		} else {
			Dprintf("Couldn't connect to bank %v:%v, %v looping\n", hostname, port, err)
			time.Sleep(1 * time.Second)
		}
	}
}

func (bc *RemoteBankClient) Notify(etx *EncryptedTransaction, _ *struct{}) error {
	return bc.client.Call("Bank.Notify", etx, nil)
}

func (bc *RemoteBankClient) Audit(a *struct{}, rep *AuditRep) error {
	return bc.client.Call("Bank.Audit", a, rep)
}

func (bc *RemoteBankClient) Store(req *StoreArgs, _ *struct{}) error {
	return bc.client.Call("Bank.Store", req, nil)
}

func (bc *RemoteBankClient) CreateEncryptedTransaction(bank_j int, value *big.Int) *EncryptedTransaction {
	log.Fatalf("remote create not implemented yet")
	return nil
}

type AuditorClient interface {
	Notify(etx *EncryptedTransaction, _ *struct{}) error
}

type LedgerClient interface {
	StartTxn(bank_i int, idx *int) error
	AppendTxn(etx *EncryptedTransaction, _ *struct{}) error
}

type IssuerClient interface {
	Issue(value *big.Int, targetBank *int) error
}

type RemoteLedgerClient struct {
	client *rpc.Client
}

func MakeRemoteLedgerClient() *RemoteLedgerClient {
	lc := &RemoteLedgerClient{}
	lc.client = nil
	return lc
}

func (lc *RemoteLedgerClient) Connect(hostname string, port int) {
	for done := false; !done; {
		c, err := rpc.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
		if err == nil {
			Dprintf("Connected to ledger %v:%v %v\n", hostname, port, err)
			lc.client = c
			done = true
		} else {
			Dprintf("Couldn't connect to ledger %v:%v %v, looping\n", hostname, port, err)
			time.Sleep(1 * time.Second)
		}
	}
}

func (lc *RemoteLedgerClient) StartTxn(bank_i int, idx *int) error {
	err := lc.client.Call("Ledger.StartTxn", bank_i, idx)
	if err != nil {
		Dprintf("StartTxn call to ledger from bank %v failed\n", bank_i)
		fmt.Println(err)
	}
	return err
}

func (lc *RemoteLedgerClient) AppendTxn(etx *EncryptedTransaction, _ *struct{}) error {
	err := lc.client.Call("Ledger.AppendTxn", etx, nil)
	if err != nil {
		Dprintf("AppendTxn call to ledger for tx %v failed\n", etx.Index)
		fmt.Println(err)
	}
	return err
}

type RemoteAuditorClient struct {
	client *rpc.Client
}

func MakeRemoteAuditorClient() *RemoteAuditorClient {
	ac := &RemoteAuditorClient{}
	return ac
}

func (ac *RemoteAuditorClient) connect(hostname string, port int) {
	for done := false; !done; {
		c, err := rpc.Dial("tcp", fmt.Sprintf("%s:%d", hostname, port))
		if err == nil {
			ac.client = c
			done = true
		} else {
			Dprintf("Couldn't connect to auditor %v:%v, looping\n", hostname, port)
			time.Sleep(1 * time.Second)
		}
	}
}

func (ac *RemoteAuditorClient) Notify(etx *EncryptedTransaction, _ *struct{}) error {
	return ac.client.Call("Auditor.Notify", etx, nil)
}
