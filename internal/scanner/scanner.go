package scanner

import (
	"fmt"
	"net"
	"time"
)

func Scan(host string, port int) {
	fmt.Printf("Hound is sniffing %s on port %d...\n", host, port)
}

func ScanPort(protocol, hostname string, port int, timeout time.Duration) {
	address := fmt.Sprintf("%s:%d", hostname, port)

	conn, err := net.DialTimeout(protocol, address, timeout)

	if err != nil {
		return
	}

	conn.Close()
	fmt.Printf("[+] Port %d is OPEN\n", port)
}
