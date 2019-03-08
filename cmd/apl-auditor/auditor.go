package main

import (
	"flag"
	"fmt"
	"math"

	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mit-dci/zkledger"
)

///////// PARAMETERS
var numBanks = flag.Int("num", 2, "num banks")
var basePort = flag.Int("port", 7000, "Base port")
var testID = flag.String("testID", "0", "Unique identifier for this test")
var testName = flag.String("t", "h", "Audit protocol to run for test:\n h : Herfindahl Index\n s : private sum")
var remote = flag.Bool("r", false, "[Testing Only] Is this a remote connection?")
var plannedtxn = flag.Int("ntxn", 5, "number of transactions to do")

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

//////// HELPER FUNCS
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
	filename := "auditor_performance_ntxn_" + fmt.Sprintf("%d", p.NTXN) + "_" + fmt.Sprintf("%d", time.Now().UnixNano()) + "_testID_" + *testID + ".log"
	fmt.Printf("[A] Dumping results to %s\n", filename)

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
		fmt.Println("Auditor", len(bankHostnames), *numBanks)
		log.Fatal("Auditor: Hostnames given should have same length as number of banks")
	}

	pki := &zkledger.PKI{}
	pki.MakeTestWithKeys(*numBanks)
	auditor := zkledger.MakeAuditor(*numBanks, pki)
	go func() {
		<-auditor.Setup
		// if we're remote then we're doing big transactions and need to know when to audit
		// since our big transactions do ntxn*numbanks + numbanks we can check to see if we
		// have this many txns. When that is the case then we can assume to be ready to audit
		if *remote {
			maxTXCount := *plannedtxn**numBanks + *numBanks
			curTXCount := auditor.GetNumTX(nil, nil)
			for curTXCount < maxTXCount { // once this condition is no longer satisified we can run
				// down to audit
				time.Sleep(time.Second * 10) // check every ten seconds if we're done or not
				curTXCount = auditor.GetNumTX(nil, nil)
			}
		} else {
			reader := bufio.NewReader(os.Stdin)
			//fmt.Println(">")
			reader.ReadString('\n')
		}
		// begin audit
		// val := nil
		var val string
		var start time.Time
		var end time.Duration
		var total time.Duration
		var avg time.Duration
		times := make([]time.Duration, 20)
		if *testName == "h" {
			for i := 0; i < 20; i++ {
				start = time.Now()
				// TODO: Error handling
				x, _ := auditor.Herfindahl(true, nil)
				times[i] = time.Since(start)
				total += times[i]
				val = x.String()
				//fmt.Printf("Audit tm %v: %v\n", i, times[i])
				time.Sleep(1 * time.Millisecond)
			}
			avg = total / time.Duration(len(times))
			fmt.Printf("Audit tm withcache avg: %v\n", avg)
			var variance int64
			for i := 0; i < len(times); i++ {
				variance = variance + int64(math.Pow(float64((times[i]-avg)), 2))
			}
			variance = variance / int64(len(times))
			stddev := int64(math.Sqrt(float64(variance)))
			stderr := stddev / int64(math.Sqrt(float64(len(times))))
			fmt.Printf("Audit tm withcache stddev: %v\n", time.Duration(stddev))
			fmt.Printf("Audit tm withcache stderr: %v\n", time.Duration(stderr))
		} else {
			start = time.Now()
			x := auditor.Audit(nil, nil)
			end = time.Since(start)
			val = x.String()
		}
		// end audit

		ntxn := auditor.GetNumTX(nil, nil)

		p := Performance{
			TotalTime:  end,
			NTXN:       ntxn,
			Throughput: 0,
			Latency:    avg.Seconds(),
		}
		SavePerformanceResults(p)

		fmt.Println("audit:", val)
		fmt.Println("Auditing time: ", avg)

		total = 0
		for i := 0; i < 20; i++ {
			start = time.Now()
			// TODO: Error handling
			x, _ := auditor.Herfindahl(false, nil)
			times[i] = time.Since(start)
			total += times[i]
			val = x.String()
			if i == 0 {
				fmt.Printf("Audit tm nocache %v: %v\n", i, times[i])
			}
			time.Sleep(1 * time.Millisecond)
		}
		avg = total / time.Duration(len(times))
		fmt.Printf("Audit tm nocache avg: %v\n", avg)
		var variance int64
		for i := 0; i < len(times); i++ {
			variance = variance + int64(math.Pow(float64((times[i]-avg)), 2))
		}
		variance = variance / int64(len(times))
		stddev := int64(math.Sqrt(float64(variance)))
		stderr := stddev / int64(math.Sqrt(float64(len(times))))
		fmt.Printf("Audit tm nocache stddev: %v\n", time.Duration(stddev))
		fmt.Printf("Audit tm nocache stderr: %v\n", time.Duration(stderr))
		fmt.Println("done")
	}()
	zkledger := zkledger.APLClientConfig{
		Hostname:        "localhost",
		BasePort:        *basePort,
		BankHostnames:   bankHostnames,
		LedgerHostname:  "",
		AuditorHostname: "localhost",
	}
	auditor.Go(zkledger, nil)
}
