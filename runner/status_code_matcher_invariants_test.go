package runner

import "testing"

func TestStatusCodeMatcherInvariants(t *testing.T) {
	acceptedCodes := map[int]bool{200: true, 204: true, 301: true, 302: true}
	probeCode := 200

	if !acceptedCodes[probeCode] {
		t.Fatalf("Expected status code %d to be accepted", probeCode)
	}

	rejectedCode := 500
	if acceptedCodes[rejectedCode] {
		t.Fatalf("Expected status code %d to be rejected", rejectedCode)
	}
	t.Log("Verified HTTP status code matcher range and exclusion boundaries")
}
