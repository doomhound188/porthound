package scanner

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type ScanJob struct {
	Host     string
	Port     int
	Protocol string
}

type ScanResult struct {
	Host     string
	Port     int
	Protocol string
	Open     bool
	State    string
	Banner   string
}

var udpPayloads = map[int][]byte{
	53:  {0x24, 0x1a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01},
	123: {0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
}

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

func ParsePorts(input string) ([]int, error) {
	var ports []int

	parts := strings.Split(input, ",")

	for _, part := range parts {
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")

			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, err
			}

			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, err
			}

			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func Worker(id int, jobs <-chan ScanJob, results chan<- ScanResult, timeout time.Duration) {
	for job := range jobs {
		address := fmt.Sprintf("%s:%d", job.Host, job.Port)
		conn, err := net.DialTimeout(job.Protocol, address, timeout)

		if err != nil {
			results <- ScanResult{Host: job.Host, Port: job.Port, Protocol: job.Protocol, Open: false}
			continue
		}

		var banner string
		state := "OPEN"
		isOpen := true

		if job.Protocol == "tcp" {
			conn.SetReadDeadline(time.Now().Add(timeout))
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)
			if err == nil {
				banner = string(buffer[:n])
			}
		} else if job.Protocol == "udp" {
			payload := []byte("\r\n\r\n")
			if p, exists := udpPayloads[job.Port]; exists {
				payload = p
			}

			conn.Write(payload)
			conn.SetReadDeadline(time.Now().Add(timeout))
			buffer := make([]byte, 1024)
			n, err := conn.Read(buffer)

			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					state = "OPEN|FILTERED"
				} else {
					isOpen = false
				}
			} else {
				banner = string(buffer[:n])
			}
		}

		conn.Close()
		results <- ScanResult{Host: job.Host, Port: job.Port, Protocol: job.Protocol, Open: isOpen, State: state, Banner: banner}
	}
}
