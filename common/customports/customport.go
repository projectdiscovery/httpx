package customport

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	sliceutil "github.com/projectdiscovery/utils/slice"

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
	potentialPorts := sliceutil.Dedupe(strings.Split(value, ","))

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
		} else if strings.HasPrefix(potentialPort, httpx.HTTPandHTTPS+":") {
			potentialPort = strings.TrimPrefix(potentialPort, httpx.HTTPandHTTPS+":")
			protocol = httpx.HTTPandHTTPS
		}

		potentialRange := strings.Split(potentialPort, "-")
		// it's a single port?
		if len(potentialRange) < portRangeParts {
			p, err := strconv.Atoi(potentialPort)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("Could not cast port to integer from your value: %s\n", potentialPort))
			}
			if err := checkPortValue(p); err != nil {
				return err
			}
			if existingProtocol, ok := Ports[p]; ok {
				if existingProtocol == httpx.HTTP && protocol == httpx.HTTPS || existingProtocol == httpx.HTTPS && protocol == httpx.HTTP {
					protocol = httpx.HTTPandHTTPS
				}
			}
			Ports[p] = protocol
		} else {
			// expand range
			lowP, err := strconv.Atoi(potentialRange[0])
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("Could not cast first port of your range(%s) to integer from your value: %s", potentialPort, potentialRange[0]))
			}
			if err := checkPortValue(lowP); err != nil {
				return errors.Wrap(err, fmt.Sprintf("first port of your range(%d)", lowP))
			}
			highP, err := strconv.Atoi(potentialRange[1])
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("Could not cast last port of your port range(%s) to integer from your value: %s", potentialPort, potentialRange[1]))
			}
			if err := checkPortValue(highP); err != nil {
				return errors.Wrap(err, fmt.Sprintf("last port of your range(%d)", lowP))
			}

			if lowP > highP {
				return fmt.Errorf("First value of port range should be lower than the last port from your range: [%d, %d]", lowP, highP)
			}

			for i := lowP; i <= highP; i++ {
				if existingProtocol, ok := Ports[i]; ok {
					if existingProtocol == httpx.HTTP && protocol == httpx.HTTPS || existingProtocol == httpx.HTTPS && protocol == httpx.HTTP {
						protocol = httpx.HTTPandHTTPS
					}
				}
				Ports[i] = protocol
			}
		}
	}

	*c = append(*c, value)
	return nil
}

func checkPortValue(port int) error {
	if port > 65535 {
		return errors.New("port value is bigger than 65535")
	}
	return nil
}
