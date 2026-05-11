package runner

import (
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/projectdiscovery/gologger"
)

// probeSecurityHeaders checks for important security headers
func (r *Runner) probeSecurityHeaders(resp *httpx.Response) {
	if resp == nil || resp.Headers == nil {
		return
	}

	hsts := resp.Headers.Get("Strict-Transport-Security")
	xcto := resp.Headers.Get("X-Content-Type-Options")

	if hsts != "" {
		gologger.Info().Msgf("[HSTS] Present: %s", hsts)
	} else {
		gologger.Warning().Msg("[HSTS] Missing - Consider adding for better security")
	}

	if xcto == "nosniff" {
		gologger.Info().Msg("[X-Content-Type-Options] nosniff")
	} else {
		gologger.Warning().Msg("[X-Content-Type-Options] Missing or incorrect")
	}
}