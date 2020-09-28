package customport

import (
	"strconv"
	"strings"
)

//nolint:gochecknoinits // this flag var needs a small refactor to avoid the use of the init function
func init() {
	Ports = make(map[int]struct{})
}

const portRangeParts = 2

// Ports to scan
var Ports map[int]struct{}

// CustomPorts definition
type CustomPorts []string

// String returns just a label
func (c *CustomPorts) String() string {
	return "Custom Ports"
}

// Set a port range
func (c *CustomPorts) Set(value string) error {
	// ports can be like nmap -p start-end,port1,port2,port3
	// splits on comma
	potentialPorts := strings.Split(value, ",")

	// check if port is a single integer value or needs to be expanded further
	for _, potentialPort := range potentialPorts {
		potentialRange := strings.Split(strings.TrimSpace(potentialPort), "-")
		// it's a single port?
		if len(potentialRange) < portRangeParts {
			if p, err := strconv.Atoi(potentialPort); err == nil {
				Ports[p] = struct{}{}
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
				Ports[i] = struct{}{}
			}
		}
	}

	*c = append(*c, value)
	return nil
}
