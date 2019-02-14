package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mit-dci/zkledger"
)

///////// PARAMETERS
var numBanks = flag.Int("num", 2, "num banks")
var curBankID = flag.Int("id", 0, "Bank id")
var basePort = flag.Int("port", 7000, "Base port")
var hostname = flag.String("hostname", "localhost", "host")
var ledgerHostname = flag.String("lh", "localhost", "ledger hostname")
var ntxn = flag.Int("ntxn", 5, "number of transactions")
var testToRun = flag.String("t", "small", "Available tests: big,small")
var testID = flag.String("testID", "0", "Unique identifier for this test")
var noTX = flag.Bool("noTX", false, "Set to true if bank will not transact")
var dumpLedger = flag.Bool("dump", false, "Dump ledger")
var pinterval = flag.Int("pinterval", 60, "How many seconds to print progress")

type hostnames []string

var bankHostnames hostnames

func (h *hostnames) String() string {
	return fmt.Sprint(*h)
}

func (h *hostnames) Set(value string) error {
	if len(*h) > 0 {
		return errors.New("hostnames flag already set")
	}
	for _, host := range strings.Split(value, ",") {
		*h = append(*h, host)
	}
	return nil
}

func init() {
	flag.Var(&bankHostnames, "bh", "comma separated list of hostnames of the banks")
}

////////////////////

/////// HELPER FUNCS
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// exists returns whether the given file or directory exists or not
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

////////////////////

type Performance struct {
	TotalTime  time.Duration // in nanoseconds
	NTXN       int
	Throughput float64
	Latency    float64
}

func SavePerformanceResults(p Performance) {
	filename := "bank_" + strconv.Itoa(*curBankID) + "_performance_ntxn_" + fmt.Sprintf("%d", p.NTXN) + "_" + fmt.Sprintf("%d", time.Now().UnixNano()) + "_testID_" + *testID + ".log"
	fmt.Printf("[%v] Dumping results to %s\n", *curBankID, filename)

	cwd, err := filepath.Abs(filepath.Dir(os.Args[0]))
	check(err)
	testDirectory := filepath.Join(cwd, *testID)
	testDirExists, err2 := exists(testDirectory)
	check(err2)

	if !testDirExists {
		os.Mkdir(testDirectory, 0777)
	}

	fullPathFilename := filepath.Join(testDirectory, filename)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.Encode(p)
	err = ioutil.WriteFile(fullPathFilename, buf.Bytes(), 0666)
	check(err)
}

func main() {
	flag.Parse()
	if len(bankHostnames) != *numBanks {
		fmt.Printf("[%v] hostnames %v\n", *curBankID, bankHostnames)
		log.Fatal("Bank: Hostnames given should have same length as number of banks")

	}
	pki := &zkledger.PKI{}
	pki.MakeTestWithKeys(*numBanks)
	bank := zkledger.MakeBank(*curBankID, *numBanks, nil, pki)
	if !(*noTX) {
		fmt.Printf("[%v] Running test %v\n", *curBankID, *testToRun)
		if *testToRun == "small" {
			go small_test(bank)
		} else if *testToRun == "big" {
			go big_test(bank)
		} else {
			go big_test(bank)
		}
	} else {
		fmt.Printf("[%v] Not running anything because noTX is set to %v\n", *curBankID, *noTX)
	}
	zkledger := zkledger.APLClientConfig{
		Hostname:        *hostname,
		BasePort:        *basePort,
		BankHostnames:   bankHostnames,
		LedgerHostname:  *ledgerHostname,
		AuditorHostname: "",
	}
	_ = zkledger
	bank.Go(zkledger, nil)
}

func small_test(bank *zkledger.Bank) {
	<-bank.Setup
	start := time.Now()
	maxIdx := 0

	if *curBankID == 0 {
		v := big.NewInt(10)
		bank.Issue(v, nil)                    // txn 0
		bank.CreateEncryptedTransaction(1, v) // txn 1 sending 10 from b0 to b1
	} else {
		time.Sleep(1 * time.Second)
		v := big.NewInt(5)
		bank.CreateEncryptedTransaction(0, v) // txn 2 sending 5 from b1 to b0
	}

	c, ok := bank.Inflight[maxIdx]
	if !ok {
		log.Fatal("hmmm")
	}
	<-c
	end := time.Since(start)

	p := Performance{
		Throughput: float64(*ntxn) / float64(end.Seconds()),
		Latency:    end.Seconds() / float64(*ntxn),
	}

	fmt.Printf("[%v] Number per second: %v\n", *curBankID, p.Throughput)
	fmt.Printf("[%v] Latency: %vs\n", *curBankID, p.Latency)

	SavePerformanceResults(p)

	if *dumpLedger {
		bank.DumpLedger(nil, nil)
	}
	fmt.Printf("done\n")

}

func big_test(bank *zkledger.Bank) {
	<-bank.Setup
	v := big.NewInt(1000000)
	bank.Issue(v, nil) // txn 0
	receiver := (*curBankID + 1) % *numBanks
	v = big.NewInt(int64(*curBankID) + 1)
	start := time.Now()
	interval := time.Now()
	maxIdx := 0
	for i := 0; i < *ntxn; i++ {
		etx := bank.CreateEncryptedTransaction(receiver, v)
		if etx.Index > maxIdx {
			maxIdx = etx.Index
		}
		if time.Since(interval) > time.Duration(*pinterval)*time.Second {
			fmt.Printf("[%v] %v / %v\n", *curBankID, i, *ntxn)
			interval = time.Now()
		}
	}
	c, ok := bank.Inflight[maxIdx]
	if !ok {
		log.Fatal("hmmm")
	}
	<-c
	end := time.Since(start)

	p := Performance{
		TotalTime:  end,
		NTXN:       *ntxn,
		Throughput: float64(*ntxn) / float64(end.Seconds()),
		Latency:    end.Seconds() / float64(*ntxn),
	}

	fmt.Printf("[%v] Transactions per second: %v\n", *curBankID, p.Throughput)
	fmt.Printf("[%v] Latency per txn: %vs\n", *curBankID, p.Latency)

	SavePerformanceResults(p)

	if *dumpLedger {
		bank.DumpLedger(nil, nil)
	}
	fmt.Printf("done\n")
}
