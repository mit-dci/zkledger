package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

var remote = flag.Bool("remote", false, "Run remotely (not localhost)")
var numBanks = flag.Int("numbanks", 2, "Number of banks")
var debug = flag.Bool("debug", false, "Run debug")
var isWindows = flag.Bool("windows", false, "Used to append '.exe' when executing files")
var user = flag.String("user", "", "Username for logging in remotely")
var auditorHostname = flag.String("ah", "localhost", "Hostname for the auditor")
var ledgerHostname = flag.String("lh", "localhost", "Hostname for the ledger")
var testName = flag.String("t", "basic", "Test to run: simple,alternateBanks10")
var skipBuilding = flag.Bool("skipBuild", false, "Skip building the files")
var skipCopying = flag.Bool("skipCopy", false, "Skip copying files to remote servers")
var parallelizeNotify = flag.Bool("pn", true, "Send notifications in parallel")
var parallelizeVerify = flag.Bool("pv", true, "Parallelize verification")
var rpOutside = flag.Bool("rp", true, "Generate 0 Range Proofs outside of lock")
var ntxn = flag.Int("ntxn", 100, "Number of transactions in simple experiment")
var reduce = flag.Bool("re", false, "Reduce size of txns")
var waitAppend = flag.Bool("wa", true, "Wait for AppendTxn to return before returning from CreateEncryptedTransaction")
var waitNotify = flag.Bool("wn", true, "Wait for ledger to notify everyone before releasing lock")
var emptyTxn = flag.Bool("et", false, "Send around empty txns and no verifying")

type hostnames []string

var bankHostsFlag hostnames
var debugString string
var sshName string
var scpName string
var binaries []string = []string{"apl-bank", "apl-ledger", "apl-auditor"}

func (h *hostnames) String() string {
	return fmt.Sprint(*h)
}

func (h *hostnames) CommaString() string {
	result := ""
	for _, host := range *h {
		result += host + ","
	}
	return result[:len(result)-1]
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
	flag.Var(&bankHostsFlag, "bh", "comma separated list of hostnames of the banks in order of IDs.  Only used if remote==true")
	if *isWindows {
		sshName = "plink"
		scpName = "pscp"
	} else {
		sshName = "ssh"
		scpName = "scp"
	}
}

func check(err error, msg ...interface{}) {
	if err != nil {
		fmt.Println(msg...)
		log.Fatal(err)
	}
}

///////// TESTS

// num_txn = txns per creating bank
// nb = num banks
// nc = number of banks creating transactions
func test_simple(testName string, num_txn int, nb int, nc int, remote bool, ac *APLConfig) {
	log.Printf("> Starting %s: [%v banks, %v txns, %v creating]\n", testName, nb, num_txn, nc)
	log.Printf(":::::::::::::::::: Starting binaries with %d banks!\n", nb)
	log.Printf("::::::::::::::::::   With %d of them transacting!\n", nc)
	tn := testName + fmt.Sprintf("_%d_%d_%d_%d", num_txn, nb, nc, time.Now().Unix())
	ae := &APLEnvironment{}
	ae.init(nb, remote, ac)
	ae.start(num_txn, tn, nc, "h")

	tally := 0
	for {
		d := <-ae.bankTally
		tally += d
		if tally == nc {
			break
		}
	}
	log.Println("::::::::::::::::::  Auditing all banks!")
	go func() {
		defer ae.AuditorWritePipe.Close()
		io.WriteString(ae.AuditorWritePipe, "\n")
	}()
	// once we get the tally, begin auditing
	<-ae.auditorStatus

	log.Println("> Killing programs")
	ae.shutdown()
	var total_th float64
	for i := 0; i < len(ae.throughput); i++ {
		total_th += ae.throughput[i]
	}
	fmt.Printf(">>> %v/%v transacting %v ntxn per bank. Total throughput: %v, Avg latency: %v, Auditing time: %v, stddev: %v, stderr: %v\n", nc, nb, num_txn, total_th, ae.latency[0], ae.auditing, ae.stddev, ae.stderr)
}

// runs test_simple many times
func test_step(testName string,
	minBankCount int, maxBankCount int, bankStep int,
	minNumTX int, maxNumTX int, txStep int,
	minTXing int, maxTXing int, txingStep int,
	remote bool,
	ac *APLConfig) {
	log.Println("> Starting " + testName +
		": \n\tBank Range [" + strconv.Itoa(minBankCount) + "," + strconv.Itoa(maxBankCount) + "]\n\t" +
		"TX Range [" + strconv.Itoa(minNumTX) + "," + strconv.Itoa(maxNumTX) + "]")

	for curBankCount := minBankCount; curBankCount <= maxBankCount; curBankCount += bankStep {
		for curTXCount := minNumTX; curTXCount <= maxNumTX; curTXCount += txStep {
			maxTransacting := maxTXing
			if maxTransacting > curBankCount {
				maxTransacting = curBankCount
			}
			for curTXingCount := minTXing; curTXingCount <= maxTransacting; curTXingCount += txingStep {
				test_simple(testName, curTXCount, curBankCount, curTXingCount, remote, ac)
			}
		}
	}
}

////////////////////////

func main() {
	flag.Parse()
	ac := &APLConfig{
		numBanks:        *numBanks,
		remote:          *remote,
		debug:           *debug,
		user:            *user,
		auditorHostname: *auditorHostname,
		ledgerHostname:  *ledgerHostname,
		bankHostnames:   bankHostsFlag,
		testName:        *testName,
	}
	if ac.debug {
		debugString = "-debug=true"
	} else {
		debugString = ""
	}

	if ac.remote {
		log.Println("Beginning remote experiment with test:", ac.testName)

		if len(ac.bankHostnames) < 2 {
			log.Fatal("Need at least 2 bank hosts to run remote experiment")
		}

		if !*skipBuilding {
			log.Println("> Compiling code for remote servers")
			build_remote()
		}
		if !*skipCopying {
			log.Println("> Binaries built! Transfering them over to servers")
			scp()
		}
	} else {
		log.Println("Beginning local experiment with test:", ac.testName)

		log.Println("> Building binaries locally")
		if !*skipBuilding {
			build_local()
		}
	}
	switch ac.testName {
	case "simple1":
		test_simple(ac.testName, *ntxn, ac.numBanks, 1, ac.remote, ac)
		break
	case "simpleall":
		test_simple(ac.testName, *ntxn, ac.numBanks, ac.numBanks, ac.remote, ac)
		break
	case "alternateBanks10":
		test_step(ac.testName,
			2, 10, 1,
			5, 5, 1,
			10, 10, 1, ac.remote, ac)
		break
	case "r50TX_herf":
		test_step(ac.testName,
			ac.numBanks, ac.numBanks, 1,
			50, 50, 50,
			ac.numBanks, ac.numBanks, 1, ac.remote, ac)
		break
	case "r1kTX_herf":
		test_step(ac.testName,
			ac.numBanks, ac.numBanks, 1,
			1000, 1000, 1,
			ac.numBanks, ac.numBanks, 1, ac.remote, ac)
		break
	default:
		log.Println("** NOT A VALID TESTNAME ** Use: simple1 OR simpleall OR alternateBanks10 OR r50TX_herf OR r1kTX_herf")
		break
	}
}
