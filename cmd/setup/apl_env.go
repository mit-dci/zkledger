package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

type APLEnvironment struct {
	Ledger  *exec.Cmd
	Auditor *exec.Cmd
	Banks   []*exec.Cmd

	LedgerReadPipe  io.ReadCloser
	AuditorReadPipe io.ReadCloser
	BankReadPipes   []io.ReadCloser

	AuditorWritePipe io.WriteCloser

	bankTally     chan int
	auditorStatus chan bool

	throughput []float64
	latency    []time.Duration
	auditing   time.Duration
	stddev     time.Duration
	stderr     time.Duration
	remote     bool
	ac         *APLConfig
}

func (ae *APLEnvironment) init(numBanks int, remote bool, ac *APLConfig) {
	ae.Banks = make([]*exec.Cmd, numBanks)
	ae.BankReadPipes = make([]io.ReadCloser, numBanks)
	ae.bankTally = make(chan int)
	ae.auditorStatus = make(chan bool)
	ae.throughput = make([]float64, numBanks)
	ae.latency = make([]time.Duration, numBanks)
	ae.remote = remote
	ae.ac = ac
}

func (ae *APLEnvironment) shutdown() {
	if ae.remote {
		ae.shutdown_remote()
	} else {
		ae.shutdown_local()
	}
}

func (ae *APLEnvironment) start(ntxn int, testID string, numBanksTransacting int, auditFunction string) {
	if ae.remote {
		ae.start_remote(ntxn, testID, numBanksTransacting, auditFunction)
	} else {
		ae.start_local(ntxn, testID, numBanksTransacting, auditFunction)
	}
}

func (ae *APLEnvironment) shutdown_local() {
	// kill the ledger
	pkill := true
	if err := ae.Ledger.Process.Kill(); err != nil {
		fmt.Printf("failed to kill ledger: %v", err)
		pkill = true
	}

	// kill the auditor
	if err := ae.Auditor.Process.Kill(); err != nil {
		fmt.Printf("failed to kill ledger: %v", err)
		pkill = true
	}

	// kill the banks
	for i := 0; i < len(ae.Banks); i++ {
		if err := ae.Banks[i].Process.Kill(); err != nil {
			fmt.Printf("failed to kill bank %v: %v", i, err)
			pkill = true
		}
	}
	if pkill {
		if err := exec.Command("pkill", "apl").Run(); err != nil {
			log.Fatalf("Fail pkill failed: %v", err)
		}
	}
	return
}

func (ae *APLEnvironment) shutdown_remote() {
	// kill the ledger
	err := ae.Ledger.Process.Kill()
	check(err, "failed to kill:", err)

	// kill the auditor
	err = ae.Auditor.Process.Kill()
	check(err, "failed to kill:", err)

	// kill the banks
	for i := 0; i < len(ae.Banks); i++ {
		cmd := ae.Banks[i]
		if err := cmd.Process.Kill(); err != nil {
			log.Fatal("failed to kill: ", err)
		}
	}

	// Double tap and directly demand the death of remote apl instances
	// we need this in order to make sure that the items are executable

	killstring := "kill $(ps aux | grep apl | awk '{ print $2}' | awk '{print $1}')"
	//killstring := "ps aux | grep apl"
	log.Println("> killing ledger")
	// ledger
	hst0Connect := ae.ac.ledgerHostname
	if *user != "" {
		hst0Connect = *user + "@" + ae.ac.ledgerHostname
	}
	cmd := exec.Command(sshName, hst0Connect, killstring)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Println("Issue killing Ledger")
		log.Println(err)
	}
	log.Println("> killing auditor")
	// auditor
	hst1Connect := ae.ac.auditorHostname
	if *user != "" {
		hst1Connect = *user + "@" + ae.ac.auditorHostname
	}
	cmd = exec.Command(sshName, hst1Connect, killstring)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Println("Issue killing Auditor")
		log.Println(err)
	}
	for i := 0; i < len(bankHostsFlag); i++ {
		hstiConnect := bankHostsFlag[i]
		if *user != "" {
			hstiConnect = *user + "@" + bankHostsFlag[i]
		}
		log.Println("> killing bank" + strconv.Itoa(i))
		cmd = exec.Command(sshName, hstiConnect, killstring)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err = cmd.Run()
		if err != nil {
			log.Println("Issue killing Bank " + strconv.Itoa(i))
			log.Println(err)
		}
	}

	return
}

func common_args(ae *APLEnvironment) []string {
	return []string{
		"-num=" + fmt.Sprintf("%d", len(ae.Banks)),
		"-pn=" + fmt.Sprintf("%v", *parallelizeNotify),
		"-pv=" + fmt.Sprintf("%v", *parallelizeVerify),
		"-rp=" + fmt.Sprintf("%v", *rpOutside),
		"-wa=" + fmt.Sprintf("%v", *waitAppend),
		"-wn=" + fmt.Sprintf("%v", *waitNotify),
		"-et=" + fmt.Sprintf("%v", *emptyTxn),
		"-re=" + fmt.Sprintf("%v", *reduce),
		debugString,
	}
}

func (ae *APLEnvironment) start_local(ntxn int, testID string, numBanksTransacting int, auditFunction string) {
	runLedger := "./apl-ledger"
	runBank := "./apl-bank"
	runAuditor := "./apl-auditor"
	localhost := "localhost"
	defaultHost := localhost
	for i := 0; i < len(ae.Banks)-1; i++ {
		defaultHost = defaultHost + "," + localhost
	}

	if *isWindows {
		log.Println("> Adjusting for Windows Machine (.exe ftw!)")
		runLedger += ".exe"
		runBank += ".exe"
		runAuditor += ".exe"
	}

	largs := append([]string{
		"-bh=" + defaultHost,
	}, common_args(ae)...)

	// start ledger
	ae.Ledger = exec.Command(runLedger, largs...)

	fmt.Println(ae.Ledger.Args)
	ae.Ledger.Stdout = os.Stdout
	ae.Ledger.Stderr = os.Stderr
	err := ae.Ledger.Start()
	check(err, "Problem with ledger")

	aargs := append([]string{
		"-bh=" + defaultHost,
		"-testID=" + testID,
		"-t=" + auditFunction,
	}, common_args(ae)...)

	// start auditor
	ae.Auditor = exec.Command(runAuditor, aargs...)
	//ae.Auditor.Stdout = os.Stdout
	ae.Auditor.Stderr = os.Stderr
	ae.AuditorReadPipe, err = ae.Auditor.StdoutPipe()
	fmt.Println(ae.Auditor.Args)
	scanner := bufio.NewScanner(ae.AuditorReadPipe)
	go func(scanner *bufio.Scanner) {
		for scanner.Scan() {
			txt := scanner.Text()
			fmt.Println(txt)
			if strings.Contains(txt, "Auditing time") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.auditing = dur
			}
			if strings.Contains(txt, "withcache stderr") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.stderr = dur
			}
			if strings.Contains(txt, "withcache stddev") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.stddev = dur
			}
			if txt == "done" {
				ae.auditorStatus <- true
			}
		}
	}(scanner)

	ae.AuditorWritePipe, err = ae.Auditor.StdinPipe()
	check(err, "Problem setting up auditor input pipe")
	err = ae.Auditor.Start()
	check(err, "Problem with auditor")

	// start banks
	args := []string{
		runBank,
		fmt.Sprintf("-num=%d", len(ae.Banks)),
		fmt.Sprintf("-ntxn=%d", ntxn),
		"-t=big",
		"-bh=" + defaultHost,
		fmt.Sprintf("-pn=%v", *parallelizeNotify),
		fmt.Sprintf("-pv=%v", *parallelizeVerify),
		fmt.Sprintf("-rp=%v", *rpOutside),
		fmt.Sprintf("-wa=%v", *waitAppend),
		fmt.Sprintf("-wn=%v", *waitNotify),
		fmt.Sprintf("-et=%v", *emptyTxn),
		fmt.Sprintf("-re=%v", *reduce),
		"-testID=" + testID,
		debugString}

	bargs := append([]string{
		"-ntxn=" + fmt.Sprintf("%d", ntxn),
		"-t=big",
		"-bh=" + defaultHost,
		"-testID=" + testID,
	}, common_args(ae)...)

	for i := 0; i < len(ae.Banks); i++ {
		if i >= numBanksTransacting { // we've reached our quota for txing banks
			if !(*isWindows) {
				ae.Banks[i] = exec.Command("sh", "-c", strings.Join(args, " ")+fmt.Sprintf(" -id=%d", i)+" -noTX=true")
			} else {
				xargs := append(bargs, []string{fmt.Sprintf("-id=%d", i), "-noTX=true"}...)
				ae.Banks[i] = exec.Command(
					runBank,
					xargs...)
			}
		} else {
			if !(*isWindows) {
				ae.Banks[i] = exec.Command("sh", "-c", strings.Join(args, " ")+fmt.Sprintf(" -id=%d", i))
			} else {
				xargs := append(bargs, []string{fmt.Sprintf("-id=%d", i)}...)
				ae.Banks[i] = exec.Command(
					runBank,
					xargs...)
			}
		}
		//ae.Banks[i].Stdout = os.Stdout
		fmt.Println(ae.Banks[i].Args)
		ae.Banks[i].Stderr = os.Stderr
		ae.BankReadPipes[i], err = ae.Banks[i].StdoutPipe()

		scanner := bufio.NewScanner(ae.BankReadPipes[i])
		go func(scanner *bufio.Scanner, i int) {
			for scanner.Scan() {
				txt := scanner.Text()
				if !strings.Contains(txt, "wrong number") && !strings.Contains(txt, "method") {
					fmt.Println(txt)
				}
				if txt == "done" {
					ae.bankTally <- 1
				}
				if strings.Contains(txt, "Transactions per second") {
					tp := strings.Trim(strings.Split(txt, ":")[1], " ")
					fmt.Println(tp)
					tpn, err := strconv.ParseFloat(tp, 64)
					if err != nil {
						panic(err)
					}
					ae.throughput[i] = tpn
				}
				if strings.Contains(txt, "Latency") {
					tp := strings.Trim(strings.Split(txt, ":")[1], " ")
					dur, err := time.ParseDuration(tp)
					if err != nil {
						panic(err)
					}
					fmt.Println(dur)
					ae.latency[i] = dur
				}
			}
		}(scanner, i)

		check(err, "failed to set up bank pipe", i)
		err = ae.Banks[i].Start()
		check(err, "Problem with bank", i)
	}
}

func (ae *APLEnvironment) start_remote(ntxn int, testID string, numBanksTransacting int, auditFunction string) {
	runLedger := "/home/" + *user + "/apl-ledger"
	runAuditor := "/home/" + *user + "/apl-auditor"
	runBank := "/home/" + *user + "/apl-bank"

	// start ledger
	hst0Connect := ae.ac.ledgerHostname
	if *user != "" {
		hst0Connect = *user + "@" + ae.ac.ledgerHostname
	}
	log.Println("> Starting Ledger!")
	ae.Ledger = exec.Command(sshName, hst0Connect,
		runLedger,
		"-num="+fmt.Sprintf("%d", len(ae.Banks)),
		"-bh="+bankHostsFlag.CommaString(),
		"-ah="+fmt.Sprintf("%v", ae.ac.auditorHostname),
		"-pn="+fmt.Sprintf("%v", *parallelizeNotify),
		"-pv="+fmt.Sprintf("%v", *parallelizeVerify),
		"-rp="+fmt.Sprintf("%v", *rpOutside),
		"-re="+fmt.Sprintf("%v", *reduce),
		"-wn="+fmt.Sprintf("%v", *waitNotify),
		"-wa="+fmt.Sprintf("%v", *waitAppend),
		"-et="+fmt.Sprintf("%v", *emptyTxn),
		debugString)
	ae.Ledger.Stdout = os.Stdout
	ae.Ledger.Stderr = os.Stderr
	err := ae.Ledger.Start()
	check(err, "Problem with ledger")
	fmt.Println(ae.Ledger.Args)
	// start auditor
	hst1Connect := *auditorHostname
	if *user != "" {
		hst1Connect = *user + "@" + *auditorHostname
	}
	log.Println("> Starting Auditor!")
	ae.Auditor = exec.Command(sshName, hst1Connect,
		runAuditor,
		"-num="+fmt.Sprintf("%d", len(ae.Banks)),
		"-bh="+bankHostsFlag.CommaString(),
		"-testID", testID,
		"-pn="+fmt.Sprintf("%v", *parallelizeNotify),
		"-pv="+fmt.Sprintf("%v", *parallelizeVerify),
		"-rp="+fmt.Sprintf("%v", *rpOutside),
		"-re="+fmt.Sprintf("%v", *reduce),
		"-wn="+fmt.Sprintf("%v", *waitNotify),
		"-wa="+fmt.Sprintf("%v", *waitAppend),
		"-et="+fmt.Sprintf("%v", *emptyTxn),
		"-t="+auditFunction,
		debugString)
	//ae.Auditor.Stdout = os.Stdout
	ae.Auditor.Stderr = os.Stderr
	ae.AuditorReadPipe, err = ae.Auditor.StdoutPipe()
	fmt.Println(ae.Auditor.Args)
	scanner := bufio.NewScanner(ae.AuditorReadPipe)
	go func(scanner *bufio.Scanner) {
		for scanner.Scan() {
			txt := scanner.Text()
			if !strings.Contains(txt, "wrong number") && !strings.Contains(txt, "method") {
				fmt.Println(txt)
			}
			if strings.Contains(txt, "Auditing time") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.auditing = dur
			}
			if strings.Contains(txt, "stderr") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.stderr = dur
			}
			if strings.Contains(txt, "stddev") {
				tp := strings.Trim(strings.Split(txt, ":")[1], " ")
				dur, err := time.ParseDuration(tp)
				if err != nil {
					panic(err)
				}
				ae.stddev = dur
			}

			if txt == "done" {
				ae.auditorStatus <- true
			}
		}
	}(scanner)

	ae.AuditorWritePipe, err = ae.Auditor.StdinPipe()
	check(err, "Problem setting up auditor input pipe")
	err = ae.Auditor.Start()
	check(err, "Problem with auditor")

	// start banks
	args := []string{runBank,
		fmt.Sprintf("-num=%d", len(ae.Banks)),
		fmt.Sprintf("-ntxn=%d", ntxn),
		"-t=big",
		"-lh=" + *ledgerHostname,
		"-bh=" + bankHostsFlag.CommaString(),
		fmt.Sprintf("-pn=%v", *parallelizeNotify),
		fmt.Sprintf("-pv=%v", *parallelizeVerify),
		fmt.Sprintf("-rp=%v", *rpOutside),
		fmt.Sprintf("-re=%v", *reduce),
		fmt.Sprintf("-wn=%v", *waitNotify),
		fmt.Sprintf("-et=%v", *emptyTxn),
		fmt.Sprintf("-wa=%v", *waitAppend),
		"-testID=" + testID,
		debugString}

	for i := 0; i < len(ae.Banks); i++ {
		hstiConnect := bankHostsFlag[i]
		if *user != "" {
			hstiConnect = *user + "@" + bankHostsFlag[i]
		}

		if i >= numBanksTransacting { // we've reached our quota for txing banks
			log.Println("> Starting bank " + strconv.Itoa(i) + " but not transacting")
			ae.Banks[i] = exec.Command("sh", "-c", sshName+" "+hstiConnect+" "+strings.Join(args, " ")+fmt.Sprintf(" -id=%d", i)+" -noTX=true")
		} else {
			log.Println("> Starting bank " + strconv.Itoa(i))
			ae.Banks[i] = exec.Command("sh", "-c", sshName+" "+hstiConnect+" "+strings.Join(args, " ")+fmt.Sprintf(" -id=%d", i))
		}
		//ae.Banks[i].Stdout = os.Stdout
		ae.Banks[i].Stderr = os.Stderr
		ae.BankReadPipes[i], err = ae.Banks[i].StdoutPipe()
		//fmt.Println(ae.Banks[i].Args)
		scanner := bufio.NewScanner(ae.BankReadPipes[i])
		go func(scanner *bufio.Scanner, i int) {
			for scanner.Scan() {
				txt := scanner.Text()

				if !strings.Contains(txt, "wrong number") && !strings.Contains(txt, "method") {
					fmt.Println(txt)
				}
				if txt == "done" {
					ae.bankTally <- 1
				}
				if strings.Contains(txt, "Transactions per second") {
					tp := strings.Trim(strings.Split(txt, ":")[1], " ")
					tpn, err := strconv.ParseFloat(tp, 64)
					if err != nil {
						panic(err)
					}
					ae.throughput[i] = tpn
				}
				if strings.Contains(txt, "Latency") {
					tp := strings.Trim(strings.Split(txt, ":")[1], " ")
					dur, err := time.ParseDuration(tp)
					if err != nil {
						panic(err)
					}
					ae.latency[i] = dur
				}

			}
		}(scanner, i)

		check(err, "failed to set up bank pipe", i)
		err = ae.Banks[i].Start()
		check(err, "Problem with bank", i)
	}
}

///////// LOCAL FUNCTIONS

func build_local() {
	for b := range binaries {
		cmd := exec.Command("go", "build", fmt.Sprintf("github.com/mit-dci/zkledger/cmd/%s", binaries[b]))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
	}
}

///////// REMOTE FUNCTIONS

func build_remote() {
	for b := range binaries {
		cmd := exec.Command("env", "GOOS=linux", "GOARCH=amd64", "go", "build", fmt.Sprintf("github.com/mit-dci/zkledger/cmd/%s", binaries[b]))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Compiled:", binaries[b])
	}
}

func scp() {
	log.Println("> Sending files to remote servers")

	runLedger := "/home/" + *user + "/apl-ledger"
	runBank := "/home/" + *user + "/apl-bank"
	runAuditor := "/home/" + *user + "/apl-auditor"

	// ledger
	hst0Connect := *ledgerHostname
	if *user != "" {
		hst0Connect = *user + "@" + *ledgerHostname + ":" + runLedger
	}

	// copy it over
	log.Println("> Sending Ledger to", *ledgerHostname)
	cmd := exec.Command(scpName, "apl-ledger", hst0Connect)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// chmod it to be executable
	cmd2 := exec.Command(sshName, hst0Connect[:len(hst0Connect)-len(runLedger)-1], "chmod 770 "+runLedger) // [:-2] removes the :~
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	err2 := cmd2.Run()
	if err2 != nil {
		log.Fatal(err2)
	}

	// auditor
	hst1Connect := *auditorHostname
	if *user != "" {
		hst1Connect = *user + "@" + *auditorHostname + ":" + runAuditor
	}

	// copy it over
	log.Println("> Sending Auditor to ", *auditorHostname)
	cmd = exec.Command(scpName, "apl-auditor", hst1Connect)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// chmod it to be executable
	cmd2 = exec.Command(sshName, hst1Connect[:len(hst1Connect)-len(runAuditor)-1], "chmod 770 "+runAuditor) // [:-2] removes the :~
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	err2 = cmd2.Run()
	if err2 != nil {
		log.Fatal(err2)
	}

	log.Println("> Sending banks to", bankHostsFlag)
	var wg sync.WaitGroup
	for i := 0; i < len(bankHostsFlag); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			hstiConnect := bankHostsFlag[i]
			if *user != "" {
				hstiConnect = *user + "@" + bankHostsFlag[i] + ":" + runBank
			}

			log.Println("> Sending bank " + strconv.Itoa(i) + " to " + bankHostsFlag[i])
			cmd = exec.Command(scpName, "apl-bank", hstiConnect)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				log.Fatal(err)
			}

			// chmod it to be executable
			cmd2 = exec.Command(sshName, hstiConnect[:len(hstiConnect)-len(runBank)-1], "chmod 770 "+runBank) // [:-2] removes the :~
			cmd2.Stdout = os.Stdout
			cmd2.Stderr = os.Stderr
			err2 = cmd2.Run()
			if err2 != nil {
				log.Fatal(err2)
			}
		}(i)
	}
	wg.Wait()
}

// TBD

type TestCase struct {
	Name          string
	NumTXN        int
	Local         bool
	MinBankCount  int
	MaxBankCount  int
	BankStep      int
	MinNumTX      int
	MaxNumTX      int
	TXStep        int
	AuditFunction string
}

type APLConfig struct {
	numBanks        int
	remote          bool
	debug           bool
	user            string
	auditorHostname string
	ledgerHostname  string
	bankHostnames   []string
	testName        string
}

///
