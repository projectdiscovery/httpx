package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// errTargetLineConflict is the error of a target line with an ip and options
// that do not keep to the ip.
var errTargetLineConflict = errors.New("options that do not keep to its ip")

// nucleiKeys are the keys a nuclei target line may hold besides target and ip,
// which select its templates. They are ignored, so that one list feeds both
// tools.
var nucleiKeys = []string{
	"profile", "templates", "tags", "exclude-tags", "include-tags", "author", "template-id",
	"exclude-id", "severity", "exclude-severity", "type", "exclude-type", "tech",
}

// targetLine is an input line: a target, pinned to an ip when IP is set. A
// line that pins it is a JSON object, in the format of nuclei target lines:
//
//	{"target": "https://app.example", "ip": "192.0.2.10"}
//
// Like curl --resolve, but on every port of its host, connections to the
// hostname go to the ip, while the hostname is kept for the Host header and
// SNI and is not resolved.
type targetLine struct {
	Target string `json:"target"`
	IP     string `json:"ip,omitempty"`
}

// readInputLine returns the form an input line is stored and deduplicated in,
// and false if the line is skipped.
func (r *Runner) readInputLine(line string) (string, bool) {
	parsed, ok := r.inputOf(line)
	return parsed.key(), ok
}

// inputOf parses an input line: an invalid line is reported and skipped, while
// a line that conflicts with the options stops the run, as every such line
// would.
func (r *Runner) inputOf(line string) (targetLine, bool) {
	parsed, err := r.parseInput(line)
	if errors.Is(err, errTargetLineConflict) {
		gologger.Fatal().Msgf("Invalid input: %s\n", err)
	}
	if err != nil {
		gologger.Error().Msgf("Skipping input: %s\n", err)
		return targetLine{}, false
	}
	return parsed, true
}

// parseInput parses an input line, and refuses a target line with an ip when
// an option does not keep to the ip.
func (r *Runner) parseInput(line string) (targetLine, error) {
	line = strings.TrimSpace(line)
	// a target line is a JSON object
	if !strings.HasPrefix(line, "{") {
		return targetLine{Target: line}, nil
	}
	parsed, err := parseTargetLine(line)
	if err != nil {
		return targetLine{}, fmt.Errorf("invalid target line %q: %w", line, err)
	}
	if parsed.IP != "" {
		if flags := r.options.targetLineConflicts(); len(flags) > 0 {
			return targetLine{}, fmt.Errorf("target line %q cannot be probed with %w: %s", line, errTargetLineConflict, strings.Join(flags, ", "))
		}
	}
	return parsed, nil
}

// key returns the line as it is stored and deduplicated: the target alone
// when it is not pinned, and a canonical target line otherwise.
func (t targetLine) key() string {
	if t.IP == "" {
		return t.Target
	}
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(t)
	return strings.TrimSpace(buf.String())
}

// parseTargetLine decodes a target line, or returns why it is invalid. Unknown
// keys and an ip that is null or empty are rejected, so that a typo cannot
// silently probe the host through DNS.
func parseTargetLine(line string) (targetLine, error) {
	// the values are kept raw to tell an ip that is null or empty from no ip
	var keys map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(line))
	if err := decoder.Decode(&keys); err != nil {
		return targetLine{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return targetLine{}, errors.New("unexpected data after the object")
	}
	if err := checkKeys(keys); err != nil {
		return targetLine{}, err
	}

	var target string
	if raw, ok := keys["target"]; ok {
		if err := json.Unmarshal(raw, &target); err != nil {
			return targetLine{}, err
		}
	}
	target = strings.TrimSpace(target)
	if target == "" {
		return targetLine{}, errors.New("no target")
	}
	rawIP, ok := keys["ip"]
	if !ok {
		return targetLine{Target: target}, nil
	}
	if err := checkPinnable(target); err != nil {
		return targetLine{}, err
	}
	ip, err := decodeIP(rawIP)
	if err != nil {
		return targetLine{}, err
	}
	return targetLine{Target: target, IP: ip}, nil
}

// checkKeys returns an error naming the keys of a target line that are neither
// target, ip nor keys of nuclei target lines.
func checkKeys(keys map[string]json.RawMessage) error {
	var unknown []string
	for key := range keys {
		if key != "target" && key != "ip" && !slices.Contains(nucleiKeys, key) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	slices.Sort(unknown)
	return fmt.Errorf("unknown keys %s (supported: target, ip and the keys of nuclei target lines)", strings.Join(unknown, ", "))
}

// decodeIP decodes and validates the ip of a target line, and returns it in
// canonical form.
func decodeIP(raw json.RawMessage) (string, error) {
	var ip string
	if err := json.Unmarshal(raw, &ip); err != nil {
		return "", err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return "", fmt.Errorf("invalid ip %q", ip)
	}
	return addr.Unmap().String(), nil
}

// checkPinnable returns why target cannot be pinned to an ip: only a single
// target with a hostname can.
func checkPinnable(target string) error {
	switch {
	case iputil.IsCIDR(target), asn.IsASN(target):
		return errors.New("a CIDR or ASN target cannot be pinned to an ip")
	case stringsutil.HasPrefixAny(target, "*", "."):
		return errors.New("a wildcard target cannot be pinned to an ip")
	case isVHostInput(target):
		return errors.New("a vhost,ip target cannot be pinned to an ip")
	}
	parsed, err := urlutil.Parse(target)
	if err != nil || parsed.Hostname() == "" || iputil.IsIP(parsed.Hostname()) {
		return errors.New("a target pinned to an ip must have a hostname")
	}
	return nil
}

// targetLineConflicts returns the options a target line with an ip cannot be
// probed with: their probes do not connect through the ip, or share a
// connection between the ips of a host, as HTTP/2 does.
func (options *Options) targetLineConflicts() []string {
	var flags []string
	if options.Unsafe {
		flags = append(flags, "-unsafe")
	}
	if options.Pipeline {
		flags = append(flags, "-pipeline")
	}
	if options.HTTP2Probe {
		flags = append(flags, "-http2")
	}
	if strings.EqualFold(options.Protocol, string(httpx.HTTP2)) {
		flags = append(flags, "-pr http2")
	}
	if options.Jarm {
		flags = append(flags, "-jarm")
	}
	if options.Screenshot {
		flags = append(flags, "-screenshot")
	}
	if options.VHostInput {
		flags = append(flags, "-vhost-input")
	}
	if options.Proxy != "" {
		flags = append(flags, "-proxy")
	}
	return flags
}
