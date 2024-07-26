package pdcp

import (
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	urlutil "github.com/projectdiscovery/utils/url"
)

func getAssetsDashBoardURL(id string) string {
	ux, _ := urlutil.Parse(pdcpauth.DashBoardURL)
	ux.Path = "/assets/" + id
	ux.Update()
	return ux.String()
}

// {"asset_id":"cqdtekhte9oc73e9hrvg","message":"Successfully uploaded asset","upload_status":"success","uploaded_at":"2024-07-20 15:27:16.148527329 +0000 UTC m=+1078.215945902"}
type uploadResponse struct {
	ID      string `json:"asset_id"`
	Message string `json:"message"`
}
