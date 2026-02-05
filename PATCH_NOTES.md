# Fix for Issue #2240: Honor -pr http11 flag

## Changes Required

This fix requires updating `common/httpx/httpx.go` to set the `DisableHTTP2` option in retryablehttp-go when the user specifies `-pr http11`.

### Location
File: `common/httpx/httpx.go`
After line 79 (where `retryablehttpOptions.Trace = options.Trace` is set)

### Code to Add
```go
// Disable HTTP/2 fallback when http11 protocol is explicitly requested
if httpx.Options.Protocol == "http11" {
	retryablehttpOptions.DisableHTTP2 = true
}
```

This ensures that when users specify `-pr http11`, the retryablehttp client will not automatically fall back to HTTP/2 on protocol errors, respecting the user's explicit HTTP/1.1-only preference.

## Dependencies
This fix depends on the DisableHTTP2 option being added to retryablehttp-go (PR #521).
