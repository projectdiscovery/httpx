#!/bin/bash

echo 'Building functional-test binary'
go build

echo 'Building HTTPX binary from current branch'
go build -o httpx_dev ../httpx

echo 'Installing latest release of HTTPX'
GO111MODULE=on go build -v github.com/projectdiscovery/httpx/cmd/httpx

echo 'Starting HTTPX functional test'
./functional-test -main ./httpx -dev ./httpx_dev -testcases testcases.txt
