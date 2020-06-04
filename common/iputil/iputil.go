package iputil

import "net"

// IsCidr determines if the given ip is a cidr range
func IsCidr(ip string) bool {
	_, _, err := net.ParseCIDR(ip)
	if err != nil {
		return false
	}

	return true
}

// IsIP determines if the given string is a valid ip
func IsIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// Ips of a cidr
func Ips(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// remove network address and broadcast address
	return ips[1 : len(ips)-1], nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
