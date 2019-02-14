package main

import (
	"flag"

	"fmt"

	"github.com/mit-dci/zkledger"
)

var num = flag.Int("num", 2, "The number of banks you want generate keys for")
var loadKeys = flag.Bool("load", false, "Loads the keys if they already exist")

func main() {
	flag.Parse()
	pki := zkledger.PKI{}
	if *loadKeys {
		pki.MakeTestWithKeys(*num)
	} else {
		pki.MakeTest(*num)
	}

	fmt.Println(pki)
}
