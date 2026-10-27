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
// connection goes to the ip.
type targetLine struct {
	Target string `json:"target"`
	IP     string `json:"ip,omitempty"`
}

// isTargetLine reports whether an input line is a target line.
func isTargetLine(line string) bool {
	return strings.HasPrefix(strings.TrimSpace(line), "{")
}

// parseTargetLine decodes a target line. Unknown keys are rejected so that a
// typo cannot silently probe the host through DNS.
func parseTargetLine(line string) (targetLine, error) {
	decoder := json.NewDecoder(strings.NewReader(line))
	decoder.DisallowUnknownFields()
	var parsed targetLine
	if err := decoder.Decode(&parsed); err != nil {
		return targetLine{}, fmt.Errorf("invalid target line %q: %w", line, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return targetLine{}, fmt.Errorf("invalid target line %q: unexpected data after the object", line)
	}

	parsed.Target = strings.TrimSpace(parsed.Target)
	if parsed.Target == "" {
		return targetLine{}, fmt.Errorf("target line %q has no target", line)
	}
	if parsed.IP == "" {
		return parsed, nil
	}
	ip, err := pinnedIP(parsed.Target, parsed.IP)
	if err != nil {
		return targetLine{}, fmt.Errorf("target %q: %w", parsed.Target, err)
	}
	parsed.IP = ip
	return parsed, nil
}

// pinnedIP validates the ip a target is pinned to and returns it in canonical
// form. Only a target with a hostname can be pinned.
func pinnedIP(target, value string) (string, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
		return "", fmt.Errorf("invalid ip %q", value)
	}
	if iputil.IsCIDR(target) || asn.IsASN(target) {
		return "", errors.New("a CIDR or ASN target cannot have an ip")
	}
	if stringsutil.HasPrefixAny(target, "*", ".") || (!stringsutil.HasPrefixAny(target, "http://", "https://") && strings.Contains(target, ",")) {
		return "", errors.New("a wildcard or vhost,ip target cannot have an ip")
	}
	parsed, err := urlutil.Parse(target)
	if err != nil || parsed.Hostname() == "" || iputil.IsIP(parsed.Hostname()) {
		return "", errors.New("a target with an ip must have a hostname")
	}
	return addr.Unmap().String(), nil
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
	line, err := parseTargetLine(item)
	if err != nil {
		return "", err
	}
	if line.IP != "" {
		if flags := r.options.pinnedTargetConflicts(); len(flags) > 0 {
			return "", fmt.Errorf("target %q: a target with an ip cannot be probed with %s", line.Target, strings.Join(flags, ", "))
		}
	}
	return line.key(), nil
}

// pinnedTargetConflicts returns the flags whose probes do not connect through
// the ip a target is pinned to, or share a connection between the ips of a
// host, as HTTP/2 does.
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
	if options.Proxy != "" || options.HTTPProxy != "" || options.SocksProxy != "" {
		flags = append(flags, "-proxy")
	}
	return flags
}
