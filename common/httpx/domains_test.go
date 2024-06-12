package httpx

import (
	_ "embed"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed test-data/hackerone.html
var rawResponse string

func TestBodyGrabDoamins(t *testing.T) {
	ht, err := New(&DefaultOptions)
	require.Nil(t, err)
	resposne := &Response{
		Raw: rawResponse,
	}
	bd := ht.BodyDomainGrab(resposne)
	
	expectedDomains := []string{
		"custom.transaction",
		"drupal.org",
		"facebook.com",
		"fonts.googleapis.com",
		"googletagmanager.com",
		"h1.community",
		"hackerone.com",
		"hackeronestatus.com",
		"instagram.com",
		"linkedin.com",
		"newrelic.com",
		"ogp.me",
		"optimizely.com",
		"purl.org",
		"rdfs.org",
		"schema.org",
		"trustarc.com",
		"twitter.com",
		"w3.org",
		"xmlns.com",
		"youtube.com",
	}

	exFqdns := []string{
		"cdn.optimizely.com",
		"consent.trustarc.com",
		"docs.hackerone.com",
		"js-agent.newrelic.com",
		"www.drupal.org",
		"www.facebook.com",
		"www.googletagmanager.com",
		"www.hackerone.com",
		"www.hackeronestatus.com",
		"www.instagram.com",
		"www.linkedin.com",
		"www.twitter.com",
		"www.w3.org",
		"www.youtube.com",
	}

	sort.Strings(bd.Domains)
	sort.Strings(bd.Fqdns)
	t.Run("body domain grab", func(t *testing.T) {
		require.Equal(t, 21, len(bd.Domains))
		require.Equal(t, 14, len(bd.Fqdns))
		require.Equal(t, expectedDomains, bd.Domains)
		require.Equal(t, exFqdns, bd.Fqdns)
	})
}
