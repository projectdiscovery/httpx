package httpx

// Target of the scan with ip|host header customization
type Target struct {
	Host       string
	CustomHost string
	CustomIP   string
}
