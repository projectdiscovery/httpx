package httpx

import (
	"fmt"
	"net"
)

// CdnCheck verifies if the given ip is part of Cdn ranges
func (h *HTTPX) CdnCheck(ip string) (bool, string, error) {
	if h.cdn == nil {
		return false, "", fmt.Errorf("cdn client not configured")
	}

	return h.cdn.CheckCDN(net.ParseIP((ip)))
}
