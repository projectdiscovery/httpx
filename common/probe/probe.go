package probe

import (
	"errors"
	"fmt"
	"strings"

	"github.com/projectdiscovery/goflags"
)

type Probe int

const (
	StatusCode Probe = iota
	TechDetect
	ContentLength
	OutputServerHeader
	OutputContentType
	OutputLinesCount
	OutputWordsCount
	OutputResponseTime
	ExtractTitle
	Location
	OutputMethod
	OutputWebSocket
	OutputIP
	OutputCName
	OutputCDN
	limit
)

var probeMappings = map[Probe]string{
	StatusCode:         "sc",
	TechDetect:         "td",
	ContentLength:      "cl",
	OutputServerHeader: "server",
	OutputContentType:  "ct",
	OutputLinesCount:   "lc",
	OutputWordsCount:   "wc",
	OutputResponseTime: "rt",
	ExtractTitle:       "title",
	Location:           "location",
	OutputMethod:       "method",
	OutputWebSocket:    "websocket",
	OutputIP:           "ip",
	OutputCName:        "cname",
	OutputCDN:          "cdn",
}

func GetSupportedProbes() Probes {
	result := Probes{}
	for index := Probe(1); index < limit; index++ {
		if result.probes == nil {
			result.probes = make(map[Probe]interface{})
		}
		result.probes[index] = struct{}{}
	}
	return result
}

func toProbe(valueToMap string) (Probe, error) {
	normalizedValue := normalizeValue(valueToMap)
	for key, currentValue := range probeMappings {
		if normalizedValue == currentValue {
			return key, nil
		}
	}
	return -1, errors.New("Invalid probe: " + valueToMap)
}

func normalizeValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func (probe Probe) String() string {
	return probeMappings[probe]
}

// Probes used by the goflags library for parsing probe list
type Probes struct {
	probes map[Probe]interface{}
}

func (probes *Probes) Set(values string) error {
	inputProbes, err := goflags.ToNormalizedStringSlice(values)
	if err != nil {
		return err
	}
	for _, inputProbe := range inputProbes {
		computedProbe, err := toProbe(inputProbe)
		if err != nil {
			return fmt.Errorf("'%s' is not a valid probe", inputProbe)
		}
		if probes.probes == nil {
			probes.probes = make(map[Probe]interface{})
		}
		probes.probes[computedProbe] = struct{}{}
	}
	return nil
}

func (probes Probes) String() string {
	var stringProbes = make([]string, 0)
	for k := range probes.probes {
		stringProbes = append(stringProbes, k.String())
	}
	return strings.Join(stringProbes, ", ")
}

func (probes *Probes) IsSet(pb Probe) bool {
	if _, ok := probes.probes[pb]; ok {
		return true
	}
	return false
}
