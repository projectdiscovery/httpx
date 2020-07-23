package httpx

import (
	"net/http"
)

type TlsData struct {
	DNSNames         []string `json:"dns_names,omitempty"`
	Emails           []string `json:"emails,omitempty"`
	CommonName       []string `json:"common_name,omitempty"`
	Organization     []string `json:"organization,omitempty"`
	IssuerCommonName []string `json:"issuer_common_name,omitempty"`
	IssuerOrg        []string `json:"issuer_organization,omitempty"`
}

func (h *HTTPX) TlsGrab(r *http.Response) *TlsData {
	if r.TLS != nil {
		var tlsdata TlsData
		for _, certificate := range r.TLS.PeerCertificates {
			tlsdata.DNSNames = append(tlsdata.DNSNames, certificate.DNSNames...)
			tlsdata.Emails = append(tlsdata.Emails, certificate.EmailAddresses...)
			tlsdata.CommonName = append(tlsdata.CommonName, certificate.Subject.CommonName)
			tlsdata.Organization = append(tlsdata.Organization, certificate.Subject.Organization...)
			tlsdata.IssuerOrg = append(tlsdata.IssuerOrg, certificate.Issuer.Organization...)
			tlsdata.IssuerCommonName = append(tlsdata.IssuerCommonName, certificate.Issuer.CommonName)
		}
		return &tlsdata
	}
	return nil
}
