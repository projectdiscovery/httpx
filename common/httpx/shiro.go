package httpx

import (
	"github.com/projectdiscovery/retryablehttp-go"
	"net/http"
)

// ShiroCheck verifies if the given target is shiro framework
func (h *HTTPX) ShiroCheck(req *retryablehttp.Request) bool {
	cookie := http.Cookie{Name: "rememberMe", Value: "1"}
	req.AddCookie(&cookie)
	resp, err := h.Do(req)
	if err != nil {
		return false
	}
	respCookie := resp.Cookie
	v, ok := respCookie["rememberMe"]
	if ok && v == "deleteMe" {
		return true
	}
	return false
}
