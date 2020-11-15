package customport

import (
	"github.com/projectdiscovery/gologger"
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
		potentialPort = strings.TrimSpace(strings.ToLower(potentialPort))
		if strings.HasPrefix(potentialPort, httpx.HTTP+":") {
			potentialPort = strings.TrimPrefix(potentialPort, httpx.HTTP+":")
			protocol = httpx.HTTP
		} else if strings.HasPrefix(potentialPort, httpx.HTTPS+":") {
			potentialPort = strings.TrimPrefix(potentialPort, httpx.HTTPS+":")
			protocol = httpx.HTTPS
		}

		potentialRange := strings.Split(potentialPort, "-")
		// it's a single port?
		if len(potentialRange) < portRangeParts {
			if p, err := strconv.Atoi(potentialPort); err == nil {
				Ports[p] = protocol
			} else {
				gologger.Warningf("Could not cast port to integer, your value: %s, resulting error %s. Skipping it\n",
					potentialPort, err.Error())
			}
		} else {
			// expand range
			var lowP, highP int
			lowP, err := strconv.Atoi(potentialRange[0])
			if err != nil {
				gologger.Warningf("Could not cast first port of your port range(%s) to integer, your value: %s, resulting error %s. Skipping it\n",
					potentialPort, potentialRange[0], err.Error())
				continue
			}
			highP, err = strconv.Atoi(potentialRange[1])
			if err != nil {
				gologger.Warningf("Could not cast last port of your port range(%s) to integer, "+
					"your value: %s, resulting error %s. Skipping it\n",
					potentialPort, potentialRange[1], err.Error())
				continue
			}

			if lowP > highP {
				gologger.Warningf("first value of port range should be lower than the last part port "+
					"in that range, your range: [%d, %d]. Skipping it\n",
					lowP, highP)
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
