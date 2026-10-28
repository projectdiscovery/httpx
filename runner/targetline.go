package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// errTargetLineConflict is the error of a target line with an ip and an option
// that does not keep to the ip.
var errTargetLineConflict = errors.New("a target pinned to an ip cannot be probed with")

// targetLine is an input line that pins a target to an ip, like
// curl --resolve, but on every port of its host:
//
//	{"target": "https://app.example", "ip": "192.0.2.10"}
//
// The target keeps its hostname for the Host header and SNI, while the
// connection goes to the ip. A line without ip is the plain target.
type targetLine struct {
	Target string `json:"target"`
	IP     string `json:"ip,omitempty"`
}

// isTargetLine reports whether an input line is a JSON object, the form of a
// target line.
func isTargetLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "{")
}

// parseTargetLine decodes and validates a target line.
func parseTargetLine(line string) (targetLine, error) {
	parsed, err := decodeTargetLine(line)
	if err != nil {
		return targetLine{}, fmt.Errorf("invalid target line %q: %w", line, err)
	}
	return parsed, nil
}

// decodeTargetLine decodes a target line, or returns why it is invalid.
// Unknown keys and an ip that is null or empty are rejected, so that a typo
// cannot silently probe the host through DNS.
func decodeTargetLine(line string) (targetLine, error) {
	// the ip is kept raw to tell an ip that is null or empty from no ip
	var decoded struct {
		Target string          `json:"target"`
		IP     json.RawMessage `json:"ip"`
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return targetLine{}, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return targetLine{}, errors.New("unexpected data after the object")
	}

	target := strings.TrimSpace(decoded.Target)
	if target == "" {
		return targetLine{}, errors.New("no target")
	}
	if decoded.IP == nil {
		return targetLine{Target: target}, nil
	}
	if err := checkPinnable(target); err != nil {
		return targetLine{}, err
	}
	var ip string
	if err := json.Unmarshal(decoded.IP, &ip); err != nil {
		return targetLine{}, err
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return targetLine{}, fmt.Errorf("invalid ip %q", ip)
	}
	return targetLine{Target: target, IP: addr.Unmap().String()}, nil
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

// targetOf returns the target of an input line: the line itself, or the
// target of a target line.
func targetOf(line string) string {
	if !isTargetLine(line) {
		return line
	}
	if parsed, err := parseTargetLine(line); err == nil {
		return parsed.Target
	}
	return line
}

// readInputLine returns the form an input line is stored and deduplicated in,
// and false if the line is skipped: an invalid line is reported and skipped,
// while a target line that conflicts with the options stops the run, as every
// such line would.
func (r *Runner) readInputLine(line string) (string, bool) {
	key, err := r.normalizeInput(line)
	if errors.Is(err, errTargetLineConflict) {
		gologger.Fatal().Msgf("Could not read input: %s\n", err)
	}
	if err != nil {
		gologger.Error().Msgf("Skipping input: %s\n", err)
		return "", false
	}
	return key, true
}

// normalizeInput validates an input line and returns the form it is stored
// and deduplicated in. A target line with an ip is refused when an option
// does not keep to the ip.
func (r *Runner) normalizeInput(line string) (string, error) {
	line = strings.TrimSpace(line)
	if !isTargetLine(line) {
		return line, nil
	}
	parsed, err := parseTargetLine(line)
	if err != nil {
		return "", err
	}
	if parsed.IP != "" {
		if flags := r.options.targetLineConflicts(); len(flags) > 0 {
			return "", fmt.Errorf("target line %q: %w %s", line, errTargetLineConflict, strings.Join(flags, ", "))
		}
	}
	return parsed.key(), nil
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
