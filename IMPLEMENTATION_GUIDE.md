# Implementation Guide: Fix for Issue #2240

## Overview
This fix ensures that httpx honors the `-pr http11` flag by preventing automatic fallback to HTTP/2 in the retryablehttp-go library.

## Prerequisites
1. The retryablehttp-go library must have the `DisableHTTP2` option available (PR #521)
2. Update go.mod to use the version of retryablehttp-go that includes this option

## Implementation Steps

### Step 1: Update common/httpx/httpx.go

**Location:** After line 79 (after `retryablehttpOptions.Trace = options.Trace`)

**Add the following code:**
```go
// Disable HTTP/2 fallback when http11 protocol is explicitly requested
// This prevents retryablehttp from automatically retrying with HTTP/2
// when HTTP/1.x errors occur, honoring the user's -pr http11 flag
if httpx.Options.Protocol == "http11" {
	retryablehttpOptions.DisableHTTP2 = true
}
```

### Step 2: Update go.mod
Update the retryablehttp-go dependency to the version that includes the DisableHTTP2 option:
```
github.com/projectdiscovery/retryablehttp-go v1.0.XXX // version with DisableHTTP2 support
```

## How It Works

### Before the Fix:
1. User runs: `httpx -u https://example.com -pr http11`
2. httpx sets `GODEBUG=http2client=0` and clears `TLSNextProto`
3. Request is made with HTTP/1.1
4. If server responds with HTTP/2 error, retryablehttp-go automatically retries with HTTPClient2 (HTTP/2)
5. **Result:** HTTP/2 is used despite `-pr http11` flag ❌

### After the Fix:
1. User runs: `httpx -u https://example.com -pr http11`
2. httpx sets `GODEBUG=http2client=0`, clears `TLSNextProto`, AND sets `DisableHTTP2 = true`
3. Request is made with HTTP/1.1
4. If server responds with HTTP/2 error, retryablehttp-go does NOT fall back to HTTP/2
5. **Result:** Only HTTP/1.1 is used, honoring the `-pr http11` flag ✅

## Testing

### Test Case 1: HTTP/1.1-only mode
```bash
httpx -u https://example.com -pr http11 -verbose
```
Expected: All requests use HTTP/1.1, no HTTP/2 fallback

### Test Case 2: Default mode (HTTP/2 allowed)
```bash
httpx -u https://example.com -verbose
```
Expected: HTTP/2 fallback still works when not explicitly disabled

### Test Case 3: HTTP/2-only mode
```bash
httpx -u https://example.com -pr http2 -verbose
```
Expected: All requests use HTTP/2

## Code Changes Summary

**File:** `common/httpx/httpx.go`
**Lines:** Insert after line 79
**Lines Added:** 5
**Lines Modified:** 0
**Lines Deleted:** 0

## Dependencies
- Requires: projectdiscovery/retryablehttp-go PR #521 to be merged
- Related Issue: projectdiscovery/httpx#2240
- Related Issue: projectdiscovery/retryablehttp-go#3

## Backward Compatibility
✅ Fully backward compatible
- Default behavior unchanged (HTTP/2 fallback still enabled)
- Only affects behavior when `-pr http11` is explicitly specified
- No breaking changes to existing APIs
