package httpx

import (
	"context"
	"net/http"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
)

func isHTTP2FallbackError(err error) bool {
	if err == nil {
		return false
	}
	errorMsg := err.Error()
	return strings.Contains(errorMsg, "malformed HTTP version \"HTTP/2\"") ||
		strings.Contains(errorMsg, "malformed HTTP response")
}

func (c *Client) NewCheckRetryFunc() retryablehttp.CheckRetryFunc {
	return func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		if c.Options.Protocol == "http11" && c.Options.DisableHTTPFallback {
			if isHTTP2FallbackError(err) {
				return false, err
			}
		}
		return retryablehttp.DefaultRetryPolicy(ctx, resp, err)
	}
}
