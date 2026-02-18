package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/doomhound188/porthound/internal/scanner"
)

func main() {
	hostPtr := flag.String("host", "127.0.0.1", "")
	workerCount := flag.Int("workers", 100, "")
	timeoutPtr := flag.Int("timeout", 500, "")
	portsPtr := flag.String("ports", "1-1024", "")
	protoPtr := flag.String("proto", "tcp", "")
	flag.Parse()

	portsList, err := scanner.ParsePorts(*portsPtr)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	var protocols []string
	protoInput := strings.ToLower(*protoPtr)
	if protoInput == "both" {
		protocols = []string{"tcp", "udp"}
	} else if protoInput == "tcp" || protoInput == "udp" {
		protocols = []string{protoInput}
	} else {
		fmt.Println("Invalid protocol. Use tcp, udp, or both.")
		os.Exit(1)
	}

	jobs := make(chan scanner.ScanJob, *workerCount)
	results := make(chan scanner.ScanResult)
	var wg sync.WaitGroup
	timeout := time.Duration(*timeoutPtr) * time.Millisecond

	for i := 0; i < *workerCount; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			scanner.Worker(workerID, jobs, results, *hostPtr, timeout)
		}(i)
	}

	go func() {
		for _, p := range portsList {
			for _, proto := range protocols {
				jobs <- scanner.ScanJob{Port: p, Protocol: proto}
			}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	fmt.Printf("Porthound is sniffing %s on %d ports (%s) with %d workers...\n", *hostPtr, len(portsList), protoInput, *workerCount)

	for res := range results {
		if res.Open {
			bannerText := ""
			if res.Banner != "" {
				cleanBanner := strings.TrimSpace(res.Banner)
				cleanBanner = strings.ReplaceAll(cleanBanner, "\n", " ")
				cleanBanner = strings.ReplaceAll(cleanBanner, "\r", "")
				bannerText = fmt.Sprintf(" [Banner: %s]", cleanBanner)
			}
			fmt.Printf("[+] %s Port %d is %s%s\n", strings.ToUpper(res.Protocol), res.Port, res.State, bannerText)
		}
	}

	fmt.Println("Scan complete.")
}
