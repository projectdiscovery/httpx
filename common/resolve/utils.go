package resolve

import (
	"net"

	"github.com/miekg/dns"
)

// ReadResolveConfig retrieve resolvers from os
func ReadResolveConfig(configFile string) ([]string, error) {
	var servers []string

	conf, err := dns.ClientConfigFromFile(configFile)
	if err != nil {
		return servers, err
	}

	for _, nameserver := range conf.Servers {
		if nameserver[0] == '[' && nameserver[len(nameserver)-1] == ']' {
			nameserver = nameserver[1 : len(nameserver)-1]
		}
		if ip := net.ParseIP(nameserver); ip != nil {
			nameserver = net.JoinHostPort(nameserver, defaultPort)
		} else {
			nameserver = dns.Fqdn(nameserver) + ":" + defaultPort
		}
		servers = append(servers, nameserver)
	}

	return servers, nil
}
