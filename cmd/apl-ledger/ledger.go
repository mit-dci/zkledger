package main

import (
	"flag"

	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/mit-dci/zkledger"
)

var num = flag.Int("num", 2, "num banks")
var basePort = flag.Int("port", 7000, "Base port")
var auditorHostname = flag.String("ah", "localhost", "auditor hostname")

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

func main() {
	flag.Parse()
	if len(bankHostnames) != *num {
		fmt.Println("Ledger", len(bankHostnames), *num)
		log.Fatal("Ledger: Hostnames given should have same length as number of banks")
	}
	ledger := zkledger.MakeLedger(*num)
	zkledger := zkledger.APLClientConfig{
		Hostname:        "",
		BasePort:        *basePort,
		BankHostnames:   bankHostnames,
		LedgerHostname:  "",
		AuditorHostname: *auditorHostname,
	}
	ledger.Go(zkledger, nil)
}
