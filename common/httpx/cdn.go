package httpx

import "net"

// CdnCheck verifies if the given ip is part of Cdn ranges
func (h *HTTPX) CdnCheck(ip string) bool {
	ok, err := h.cdn.Check(net.ParseIP((ip)))

	return ok && err == nil
}
