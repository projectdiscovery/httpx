package httputilz

import "net/http"

// AllHTTPMethods contains all available HTTP methods
func AllHTTPMethods() []string {
	return []string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	}
}
