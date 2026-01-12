package inputformats

import (
	"strings"
	"testing"
)

func TestBurpFormat_Name(t *testing.T) {
	b := NewBurpFormat()
	if b.Name() != "burp" {
		t.Errorf("Expected name 'burp', got '%s'", b.Name())
	}
}

func TestBurpFormat_Parse(t *testing.T) {
	burpXML := `<?xml version="1.0"?>
<items burpVersion="2023.10.1.2" exportTime="Sat Sep 30 20:11:44 IST 2023">
  <item>
    <time>Sat Sep 30 20:11:32 IST 2023</time>
    <url><![CDATA[http://example.com/path1]]></url>
    <host ip="127.0.0.1">example.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/path1]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[R0VUIC8gSFRUUC8xLjE=]]></request>
    <status>200</status>
    <responselength>100</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9L]]></response>
    <comment></comment>
  </item>
  <item>
    <time>Sat Sep 30 20:08:54 IST 2023</time>
    <url><![CDATA[https://example.com/path2]]></url>
    <host ip="127.0.0.1">example.com</host>
    <port>443</port>
    <protocol>https</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/path2]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[UE9TVCAvIEhUVFAvMS4x]]></request>
    <status>200</status>
    <responselength>100</responselength>
    <mimetype>JSON</mimetype>
    <response base64="true"><![CDATA[SFRUUC8xLjEgMjAwIE9L]]></response>
    <comment></comment>
  </item>
</items>`

	b := NewBurpFormat()
	var urls []string

	err := b.Parse(strings.NewReader(burpXML), func(url string) bool {
		urls = append(urls, url)
		return true
	})

	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(urls) != 2 {
		t.Errorf("Expected 2 URLs, got %d", len(urls))
	}

	expectedURLs := []string{"http://example.com/path1", "https://example.com/path2"}
	if len(urls) != len(expectedURLs) {
		t.Fatalf("Expected %d URLs, got %d: %v", len(expectedURLs), len(urls), urls)
	}
	for i, expected := range expectedURLs {
		if urls[i] != expected {
			t.Errorf("Expected URL %d to be '%s', got '%s'", i, expected, urls[i])
		}
	}
}

func TestBurpFormat_ParseEmpty(t *testing.T) {
	burpXML := `<?xml version="1.0"?>
<items burpVersion="2023.10.1.2" exportTime="Sat Sep 30 20:11:44 IST 2023">
</items>`

	b := NewBurpFormat()
	var urls []string

	err := b.Parse(strings.NewReader(burpXML), func(url string) bool {
		urls = append(urls, url)
		return true
	})

	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(urls) != 0 {
		t.Errorf("Expected 0 URLs, got %d", len(urls))
	}
}

func TestBurpFormat_ParseStopEarly(t *testing.T) {
	burpXML := `<?xml version="1.0"?>
<items burpVersion="2023.10.1.2" exportTime="Sat Sep 30 20:11:44 IST 2023">
  <item>
    <url><![CDATA[http://example.com/1]]></url>
    <host>example.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/1]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[R0VUIC8=]]></request>
    <status>200</status>
    <responselength>100</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true"><![CDATA[T0s=]]></response>
    <comment></comment>
  </item>
  <item>
    <url><![CDATA[http://example.com/2]]></url>
    <host>example.com</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/2]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[R0VUIC8=]]></request>
    <status>200</status>
    <responselength>100</responselength>
    <mimetype>HTML</mimetype>
    <response base64="true"><![CDATA[T0s=]]></response>
    <comment></comment>
  </item>
</items>`

	b := NewBurpFormat()
	var urls []string

	err := b.Parse(strings.NewReader(burpXML), func(url string) bool {
		urls = append(urls, url)
		return false // stop after first
	})

	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if len(urls) != 1 {
		t.Errorf("Expected 1 URL (stopped early), got %d", len(urls))
	}
}

func TestBurpFormat_ParseMalformed(t *testing.T) {
	malformedXML := `<?xml version="1.0"?>
<items burpVersion="2023.10.1.2">
  <item>
    <url><![CDATA[http://example.com/path1]]></url>
    <!-- missing closing tags -->
</items>`

	b := NewBurpFormat()
	err := b.Parse(strings.NewReader(malformedXML), func(url string) bool {
		return true
	})

	if err == nil {
		t.Error("Expected error for malformed XML, got nil")
	}
}
