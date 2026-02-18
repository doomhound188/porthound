package main

import (
	"flag"
	"time"

	"github.com/doomhound188/porthound/internal/scanner"
)

func main() {
	hostPtr := flag.String("host", "172.0.0.1", "The hostname or IP to sniff")
	timeoutPtr := flag.Int("timeout", 500, "Timeout in milliseconds")

	flag.Parse()

	timeout := time.Duration(*timeoutPtr) * time.Microsecond

	for i := 1; i <= 1024; i++ {
		scanner.ScanPort("tcp", *hostPtr, i, timeout)
	}
}
