package httpx

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

// TLSData contains the relevant Transport Layer Security information
type TLSData struct {
	TLSVersion               string   `json:"tls_version,omitempty"`
	ExtensionServerName      string   `json:"extension_server_name,omitempty"`
	DNSNames                 []string `json:"dns_names,omitempty"`
	Emails                   []string `json:"emails,omitempty"`
	CommonName               []string `json:"common_name,omitempty"`
	Organization             []string `json:"organization,omitempty"`
	IssuerCommonName         []string `json:"issuer_common_name,omitempty"`
	IssuerOrg                []string `json:"issuer_organization,omitempty"`
	FingerprintSHA256        string   `json:"fingerprint_sha256,omitempty"`
	FingerprintSHA256OpenSSL string   `json:"fingerprint_sha256_openssl,omitempty"`
}

// TLSGrab fills the TLSData
func (h *HTTPX) TLSGrab(r *http.Response) *TLSData {
	if r.TLS != nil {
		var tlsdata TLSData
		// Only PeerCertificates[0] contains useful information
		cert := r.TLS.PeerCertificates[0]
		tlsdata.DNSNames = append(tlsdata.DNSNames, cert.DNSNames...)
		tlsdata.Emails = append(tlsdata.Emails, cert.EmailAddresses...)
		tlsdata.CommonName = append(tlsdata.CommonName, cert.Subject.CommonName)
		tlsdata.Organization = append(tlsdata.Organization, cert.Subject.Organization...)
		tlsdata.IssuerOrg = append(tlsdata.IssuerOrg, cert.Issuer.Organization...)
		tlsdata.IssuerCommonName = append(tlsdata.IssuerCommonName, cert.Issuer.CommonName)
		tlsdata.ExtensionServerName = r.TLS.ServerName
		if v, ok := tlsVersionStringMap[r.TLS.Version]; ok {
			tlsdata.TLSVersion = v
		}

		if fingerprintSHA256, err := calculateFingerprints(r); err == nil {
			tlsdata.FingerprintSHA256 = asHex(fingerprintSHA256)
			tlsdata.FingerprintSHA256OpenSSL = asOpenSSL(fingerprintSHA256)
		}
		return &tlsdata
	}
	return nil
}

var tlsVersionStringMap = map[uint16]string{
	0x0300: "SSL30",
	0x0301: "TLS10",
	0x0302: "TLS11",
	0x0303: "TLS12",
	0x0304: "TLS13",
}

func calculateFingerprints(r *http.Response) (fingerprintSHA256 []byte, err error) {
	if len(r.TLS.PeerCertificates) == 0 {
		err = errors.New("no certificates found")
		return
	}

	cert := r.TLS.PeerCertificates[0]
	dataSHA256 := sha256.Sum256(cert.Raw)
	fingerprintSHA256 = dataSHA256[:]
	return
}

func asOpenSSL(b []byte) string {
	var buf bytes.Buffer
	for i, f := range b {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}

func asHex(b []byte) string {
	return hex.EncodeToString(b)
}
