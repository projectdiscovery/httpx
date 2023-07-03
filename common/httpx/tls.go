package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"

	"github.com/projectdiscovery/tlsx/pkg/tlsx/clients"
	"github.com/projectdiscovery/tlsx/pkg/tlsx/ztls"
	zmaptls "github.com/zmap/zcrypto/tls"
)

// versionToTLSVersionString converts tls version to version string
var versionToTLSVersionString = map[uint16]string{
	tls.VersionTLS10: "tls10",
	tls.VersionTLS11: "tls11",
	tls.VersionTLS12: "tls12",
	tls.VersionTLS13: "tls13",
}

// TLSGrab fills the TLSData
func (h *HTTPX) TLSGrab(r *http.Response) *clients.Response {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	host := r.Request.URL.Host
	hostname, port, _ := net.SplitHostPort(host)
	if hostname == "" {
		hostname = host
	}
	if port == "" {
		port = "443"
	}

	tlsVersion := versionToTLSVersionString[r.TLS.Version]
	tlsCipher := tls.CipherSuiteName(r.TLS.CipherSuite)

	leafCertificate := r.TLS.PeerCertificates[0]
	response := &clients.Response{
		Host:                hostname,
		ProbeStatus:         true,
		Port:                port,
		Version:             tlsVersion,
		Cipher:              tlsCipher,
		TLSConnection:       "ctls",
		CertificateResponse: convertCertificateToResponse(hostname, leafCertificate),
		ServerName:          r.TLS.ServerName,
	}
	return response
}

func (h *HTTPX) ZTLSGrab(r *http.Response) *clients.Response {
	host := r.Request.URL.Host
	hostname, port, _ := net.SplitHostPort(host)
	if hostname == "" {
		hostname = host
	}
	if port == "" {
		port = "443"
	}
	// canonical net concatenation
	host = net.JoinHostPort(hostname, fmt.Sprint(port))
	tlsConn, err := h.Dialer.DialTLS(r.Request.Context(), "tcp", host)
	if err != nil {
		return nil
	}
	ztlsConn, ok := (tlsConn).(*zmaptls.Conn)
	if !ok {
		return nil
	}
	ztlsState := ztlsConn.ConnectionState()
	if len(ztlsState.PeerCertificates) == 0 {
		return nil
	}
	response := &clients.Response{
		Host:                hostname,
		ProbeStatus:         true,
		Port:                port,
		Version:             versionToTLSVersionString[ztlsState.Version],
		Cipher:              tls.CipherSuiteName(ztlsState.CipherSuite),
		TLSConnection:       "ztls",
		CertificateResponse: ztls.ConvertCertificateToResponse(&clients.Options{}, hostname, ztlsState.PeerCertificates[0]),
		ServerName:          ztlsState.ServerName,
	}
	return response
}

func convertCertificateToResponse(hostname string, cert *x509.Certificate) *clients.CertificateResponse {
	response := &clients.CertificateResponse{
		SubjectAN:    cert.DNSNames,
		Emails:       cert.EmailAddresses,
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		Expired:      clients.IsExpired(cert.NotAfter),
		SelfSigned:   clients.IsSelfSigned(cert.AuthorityKeyId, cert.SubjectKeyId),
		MisMatched:   clients.IsMisMatchedCert(hostname, append(cert.DNSNames, cert.Subject.CommonName)),
		WildCardCert: clients.IsWildCardCert(append(cert.DNSNames, cert.Subject.CommonName)),
		IssuerCN:     cert.Issuer.CommonName,
		IssuerOrg:    cert.Issuer.Organization,
		SubjectCN:    cert.Subject.CommonName,
		SubjectOrg:   cert.Subject.Organization,
		FingerprintHash: clients.CertificateResponseFingerprintHash{
			MD5:    clients.MD5Fingerprint(cert.Raw),
			SHA1:   clients.SHA1Fingerprint(cert.Raw),
			SHA256: clients.SHA256Fingerprint(cert.Raw),
		},
	}
	response.IssuerDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawIssuer, cert.Issuer.String())
	response.SubjectDN = clients.ParseASN1DNSequenceWithZpkixOrDefault(cert.RawSubject, cert.Subject.String())
	return response
}
