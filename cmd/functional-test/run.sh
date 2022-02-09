#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building functional-test binary"
go build -o functional-test$extension
echo "::endgroup::"

echo "::group::Building dnsx binary from current branch"
go build -o httpx_dev$extension ../httpx
echo "::endgroup::"

echo "::group::Building latest release of dnsx"
go build -o httpx$extension -v github.com/projectdiscovery/httpx/cmd/httpx
echo "::endgroup::"

echo 'Starting dnsx functional test'
./functional-test$extension -main ./httpx$extension -dev ./httpx_dev$extension -testcases testcases.txt
