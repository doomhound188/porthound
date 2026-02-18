package scanner

import (
	"net"
	"strings"
)

func ParseHosts(input string) ([]string, error) {
	var hosts []string
	parts := strings.Split(input, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "/") {
			ip, ipnet, err := net.ParseCIDR(part)
			if err != nil {
				return nil, err
			}

			for t := ip.Mask(ipnet.Mask); ipnet.Contains(t); inc(t) {
				hosts = append(hosts, t.String())
			}
		} else {
			hosts = append(hosts, part)
		}
	}
	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
