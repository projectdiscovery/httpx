#!/bin/bash

# Script to apply the fix for issue #2240
# This adds the DisableHTTP2 option when -pr http11 is specified

FILE="common/httpx/httpx.go"
BACKUP="common/httpx/httpx.go.backup"

# Create backup
cp "$FILE" "$BACKUP"

# The fix: Insert after line 79 (after retryablehttpOptions.Trace = options.Trace)
# We need to add:
#	// Disable HTTP/2 fallback when http11 protocol is explicitly requested
#	// This prevents retryablehttp from automatically retrying with HTTP/2
#	// when HTTP/1.x errors occur, honoring the user's -pr http11 flag
#	if httpx.Options.Protocol == "http11" {
#		retryablehttpOptions.DisableHTTP2 = true
#	}

# Using sed to insert after the line containing "retryablehttpOptions.Trace = options.Trace"
sed -i '/retryablehttpOptions.Trace = options.Trace/a\
\t// Disable HTTP/2 fallback when http11 protocol is explicitly requested\
\t// This prevents retryablehttp from automatically retrying with HTTP/2\
\t// when HTTP/1.x errors occur, honoring the user'"'"'s -pr http11 flag\
\tif httpx.Options.Protocol == "http11" {\
\t\tretryablehttpOptions.DisableHTTP2 = true\
\t}' "$FILE"

echo "Fix applied to $FILE"
echo "Backup saved to $BACKUP"
echo ""
echo "Please review the changes with: git diff $FILE"
