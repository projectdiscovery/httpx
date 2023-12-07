package httpx

import (
	"fmt"
	"net"
)

// CdnCheck verifies if the given ip is part of Cdn/WAF ranges
func (h *HTTPX) CdnCheck(ip string) (bool, string, error) {
	if h.cdn == nil {
		return false, "", fmt.Errorf("cdn client not configured")
	}

	// the goal is to check if ip is part of cdn/waf to decide if target should be scanned or not
	// since 'cloud' itemtype does not fit logic here , we consider target is not part of cdn/waf
	matched, value, itemType, err := h.cdn.Check(net.ParseIP((ip)))
	if itemType == "cloud" {
		return false, "", err
	}
	return matched, value, err
}
