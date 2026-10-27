package runner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/mapcidr/asn"
	iputil "github.com/projectdiscovery/utils/ip"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

// targetLine is an input line that pins a target to an ip, like
// curl --resolve:
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

// parseTargetLine decodes and validates a target line. Unknown keys and an ip
// that is null or empty are rejected, so that a typo cannot silently probe the
// host through DNS.
func parseTargetLine(line string) (targetLine, error) {
	// the ip is kept raw to tell an ip that is null or empty from no ip
	var decoded struct {
		Target string          `json:"target"`
		IP     json.RawMessage `json:"ip"`
	}
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return targetLine{}, invalidTargetLine(line, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return targetLine{}, invalidTargetLine(line, errors.New("unexpected data after the object"))
	}

	target := strings.TrimSpace(decoded.Target)
	if target == "" {
		return targetLine{}, invalidTargetLine(line, errors.New("no target"))
	}
	if decoded.IP == nil {
		return targetLine{Target: target}, nil
	}
	var ip string
	if err := json.Unmarshal(decoded.IP, &ip); err != nil {
		return targetLine{}, invalidTargetLine(line, err)
	}
	if err := checkPinnable(target); err != nil {
		return targetLine{}, invalidTargetLine(line, err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return targetLine{}, invalidTargetLine(line, fmt.Errorf("invalid ip %q", ip))
	}
	return targetLine{Target: target, IP: addr.Unmap().String()}, nil
}

func invalidTargetLine(line string, reason error) error {
	return fmt.Errorf("invalid target line %q: %w", line, reason)
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

// isVHostInput reports whether target is a vhost,ip input.
func isVHostInput(target string) bool {
	return !stringsutil.HasPrefixAny(target, "http://", "https://") && stringsutil.ContainsAny(target, ",")
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

// pinnedKey returns key for a target that is not pinned, and key@ip for one
// pinned to ip, as the ips of a host fail and respond independently.
func pinnedKey(key, ip string) string {
	if ip == "" {
		return key
	}
	return key + "@" + ip
}

// targetOf returns the target of an input line: the line itself, or the
// target of a target line.
func targetOf(item string) string {
	if !isTargetLine(item) {
		return item
	}
	if line, err := parseTargetLine(item); err == nil {
		return line.Target
	}
	return item
}

// normalizeInput validates an input line and returns the form it is stored
// and deduplicated in.
func (r *Runner) normalizeInput(item string) (string, error) {
	item = strings.TrimSpace(item)
	if !isTargetLine(item) {
		return item, nil
	}
	line, err := r.parseInputLine(item)
	if err != nil {
		return "", err
	}
	return line.key(), nil
}

// parseInputLine parses a target line, and refuses one pinned to an ip with
// the options that do not keep to it.
func (r *Runner) parseInputLine(item string) (targetLine, error) {
	line, err := parseTargetLine(item)
	if err != nil {
		return targetLine{}, err
	}
	if line.IP != "" {
		if flags := r.options.pinnedTargetConflicts(); len(flags) > 0 {
			return targetLine{}, invalidTargetLine(item, fmt.Errorf("a target pinned to an ip cannot be probed with %s", strings.Join(flags, ", ")))
		}
	}
	return line, nil
}

// pinnedTargetConflicts returns the options whose probes do not connect
// through the ip a target is pinned to, or share a connection between the ips
// of a host, as HTTP/2 does.
func (options *Options) pinnedTargetConflicts() []string {
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
