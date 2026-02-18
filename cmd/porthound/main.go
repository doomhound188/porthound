package main

import (
	"flag"
	"fmt"
	"sync"
	"time"

	"github.com/doomhound188/porthound/internal/scanner"
)

func main() {
	hostPtr := flag.String("host", "127.0.0.1", "")
	workerCount := flag.Int("workers", 100, "")
	timeoutPtr := flag.Int("timeout", 500, "")
	flag.Parse()

	ports := make(chan int, *workerCount)
	results := make(chan int)
	var wg sync.WaitGroup
	timeout := time.Duration(*timeoutPtr) * time.Millisecond

	for i := 0; i < *workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			scanner.Worker(workerID, ports, results, *hostPtr, timeout)
		}(i)
	}

	go func() {
		for i := 1; i <= 1024; i++ {
			ports <- i
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("Porthound is sniffing %s with %d workers...\n", *hostPtr, *workerCount)

	for res := range results {
		if res != 0 {
			fmt.Printf("[+] Port %d is OPEN\n", res)
		}
	}

	fmt.Println("Scan complete.")
}
