package zkledger

import (
	"flag"
	"fmt"
)

var DEBUG = flag.Bool("debug", false, "Debug output")

func Dprintf(format string, args ...interface{}) {
	if *DEBUG {
		fmt.Printf(format, args...)
	}
}
