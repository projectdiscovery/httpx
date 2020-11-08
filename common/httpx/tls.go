package httpx

import (
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/projectdiscovery/httpx/common/cache"
	"net/http"
)

type CertificateBlock struct {
	Envelope map[string]string `json:"env,omitempty"`
	Payload  []byte            `json:"payload,omitempty"`
}

type CertificateFold struct {
	Certificate []CertificateBlock `json:"cert,omitempty"`
	CertFold    bool               `json:"-"`
}

// TLSData contains the relevant Transport Layer Security information
type TLSDataCore struct {
	DNSNames         []string `json:"dns_names,omitempty"`
	Emails           []string `json:"emails,omitempty"`
	CommonName       []string `json:"common_name,omitempty"`
	Organization     []string `json:"organization,omitempty"`
	IssuerCommonName []string `json:"issuer_common_name,omitempty"`
	IssuerOrg        []string `json:"issuer_organization,omitempty"`
}

type TLSData struct {
	TLSDataCore
	CertificateFold
}

// marshal TLSData using CertFold to determine if the subtree should be filtered
func (t TLSData) MarshalJSON() ([]byte, error) {
	tx := TLSDataCore{
		t.DNSNames,
		t.Emails,
		t.CommonName,
		t.Organization,
		t.IssuerCommonName,
		t.IssuerOrg,
	}
	if t.CertFold {
		return json.Marshal(tx)
	}
	return json.Marshal(struct {
		TLSDataCore
		CertificateFold
	}{
		tx,
		CertificateFold{t.Certificate, false},
	})
}

// TLSGrab fills the TLSData
func (h *HTTPX) TLSGrab(r *http.Response) *TLSData {
	if r.TLS != nil {
		var tlsdata TLSData
		for _, certificate := range r.TLS.PeerCertificates {
			tlsdata.DNSNames = append(tlsdata.DNSNames, certificate.DNSNames...)
			tlsdata.Emails = append(tlsdata.Emails, certificate.EmailAddresses...)
			tlsdata.CommonName = append(tlsdata.CommonName, certificate.Subject.CommonName)
			tlsdata.Organization = append(tlsdata.Organization, certificate.Subject.Organization...)
			tlsdata.IssuerOrg = append(tlsdata.IssuerOrg, certificate.Issuer.Organization...)
			tlsdata.IssuerCommonName = append(tlsdata.IssuerCommonName, certificate.Issuer.CommonName)
			tlsdata.CertFold = true
			block := &pem.Block{Type: "CERTIFICATE", Bytes: []byte(certificate.Raw)}
			tlsdata.Certificate = append(tlsdata.Certificate, CertificateBlock{map[string]string{
				"version":    fmt.Sprintf("%d", r.TLS.Version),
				"host":       r.Request.Host,
				"sni":        r.TLS.ServerName,
				"ip":         cache.GetDialedIP(r.Request.Host),
				"cipher":     fmt.Sprintf("%d", r.TLS.CipherSuite),
				"ciphername": fmt.Sprintf("%s", tls.CipherSuiteName(r.TLS.CipherSuite)),
			}, pem.EncodeToMemory(block)})
		}
		return &tlsdata
	}
	return nil
}
