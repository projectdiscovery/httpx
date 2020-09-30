package customport

import (
	"strconv"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
)

//nolint:gochecknoinits // this flag var needs a small refactor to avoid the use of the init function
func init() {
	Ports = make(map[int]string)
}

const portRangeParts = 2

// Ports to scan
var Ports map[int]string

// CustomPorts definition
type CustomPorts []string

// String returns just a label
func (c *CustomPorts) String() string {
	return "Custom Ports"
}

// Set a port range
func (c *CustomPorts) Set(value string) error {
	// ports can be like nmap -p [https|http:]start-end,[https|http:]port1,[https|http:]port2,[https|http:]port3
	// splits on comma
	potentialPorts := strings.Split(value, ",")

	// check if port is a single integer value or needs to be expanded further
	for _, potentialPort := range potentialPorts {
		protocol := httpx.HTTPorHTTPS
		potenialPort := strings.ToLower(potentialPort)
		if strings.HasPrefix(potenialPort, httpx.HTTP+":") {
			potentialPort = strings.TrimPrefix(potenialPort, httpx.HTTP+":")
			protocol = httpx.HTTP
		}
		if strings.HasPrefix(potenialPort, httpx.HTTPS+":") {
			potentialPort = strings.TrimPrefix(potenialPort, httpx.HTTPS+":")
			protocol = httpx.HTTPS
		}

		potentialRange := strings.Split(strings.TrimSpace(potentialPort), "-")
		// it's a single port?
		if len(potentialRange) < portRangeParts {
			if p, err := strconv.Atoi(potentialPort); err == nil {
				Ports[p] = protocol
			}
		} else {
			// expand range
			var lowP, highP int
			lowP, err := strconv.Atoi(potentialRange[0])
			if err != nil {
				continue
			}
			highP, err = strconv.Atoi(potentialRange[1])
			if err != nil {
				continue
			}
			for i := lowP; i <= highP; i++ {
				Ports[i] = protocol
			}
		}
	}

	*c = append(*c, value)
	return nil
}
