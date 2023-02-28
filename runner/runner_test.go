package runner

import (
	"os"
	"strings"
	"testing"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/httpx/common/httpx"
	"github.com/stretchr/testify/require"
)

func TestRunner_domain_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := []string{"example.com", "*.example.com", "example.com,one.one.one.one"}
	expected := []httpx.Target{{
		Host: "example.com",
	}, {
		Host: "example.com",
	}, {
		Host:       "one.one.one.one",
		CustomHost: "example.com",
	}}
	got := []httpx.Target{}
	for _, inp := range input {
		for target := range r.targets(r.hp, inp) {
			got = append(got, target)
		}
	}
	require.ElementsMatch(t, expected, got, "could not exepcted output")
}

func TestRunner_probeall_targets(t *testing.T) {
	options := &Options{
		ProbeAllIPS: true,
	}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "one.one.one.one"
	expected := []httpx.Target{{
		Host:     "one.one.one.one",
		CustomIP: "2606:4700:4700::1111",
	},
		{
			Host:     "one.one.one.one",
			CustomIP: "2606:4700:4700::1001",
		},
		{
			Host:     "one.one.one.one",
			CustomIP: "1.0.0.1",
		},
		{
			Host:     "one.one.one.one",
			CustomIP: "1.1.1.1",
		}}
	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}

	require.ElementsMatch(t, expected, got, "could not exepcted output")
}

func TestRunner_cidr_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "173.0.84.0/30"
	expected := []httpx.Target{
		{
			Host: "173.0.84.0",
		}, {
			Host: "173.0.84.1",
		},
		{
			Host: "173.0.84.2",
		},
		{
			Host: "173.0.84.3",
		}}
	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}

	require.ElementsMatch(t, expected, got, "could not exepcted output")
}

func TestRunner_asn_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := "AS14421"
	expected := []httpx.Target{}
	expectedOutputFile := "tests/AS14421.txt"
	// read the expected IPs from the file
	fileContent, err := os.ReadFile(expectedOutputFile)
	require.Nil(t, err, "could not read the expectedOutputFile file")
	ips := strings.Split(strings.ReplaceAll(string(fileContent), "\r\n", "\n"), "\n")
	for _, ip := range ips {
		expected = append(expected, httpx.Target{Host: ip})
	}
	got := []httpx.Target{}
	for target := range r.targets(r.hp, input) {
		got = append(got, target)
	}
	require.ElementsMatch(t, expected, got, "could not exepcted output")
}

func TestRunner_countTargetFromRawTarget(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")

	input := "example.com"
	expected := 1
	got := r.countTargetFromRawTarget(input)
	require.Equal(t, expected, got, "got wrong output")

	input = "example.com"
	expected = 0
	err = r.hm.Set(input, nil)
	require.Nil(t, err, "could not set value to hm")
	got = r.countTargetFromRawTarget(input)
	require.Equal(t, expected, got, "got wrong output")

	input = ""
	expected = 0
	got = r.countTargetFromRawTarget(input)
	require.Equal(t, expected, got, "got wrong output")

	input = "AS14421"
	expected = 256
	got = r.countTargetFromRawTarget(input)
	require.Equal(t, expected, got, "got wrong output")

	input = "173.0.84.0/24"
	expected = 256
	got = r.countTargetFromRawTarget(input)
	require.Equal(t, expected, got, "got wrong output")
}

func TestRunner_urlWithComma_targets(t *testing.T) {
	options := &Options{}
	r, err := New(options)
	require.Nil(t, err, "could not create httpx runner")
	input := []string{"http://scanme.sh?a=1,2"}
	expected := []httpx.Target{{
		Host: "http://scanme.sh?a=1,2",
	}}
	got := []httpx.Target{}
	for _, inp := range input {
		for target := range r.targets(r.hp, inp) {
			got = append(got, target)
		}
	}
	require.ElementsMatch(t, expected, got, "could not exepcted output")
}
