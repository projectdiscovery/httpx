package httpx

import (
	"fmt"

	"github.com/hbakhtiyor/strsim"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
	"github.com/rs/xid"
)

const simMultiplier = 100

// IsVirtualHost checks if the target endpoint is a virtual host
func (h *HTTPX) IsVirtualHost(req *retryablehttp.Request, unsafeOptions UnsafeOptions) (bool, error) {
	httpresp1, err := h.Do(req, unsafeOptions)
	if err != nil {
		return false, err
	}

	// request a non-existing endpoint
	req.Host = fmt.Sprintf("%s.%s", xid.New().String(), req.Host)

	httpresp2, err := h.Do(req, unsafeOptions)
	if err != nil {
		return false, err
	}

	// Status Code
	if !h.Options.VHostIgnoreStatusCode && httpresp1.StatusCode != httpresp2.StatusCode {
		return true, nil
	}

	// Content - Bytes Length
	if !h.Options.VHostIgnoreContentLength && httpresp1.ContentLength != httpresp2.ContentLength {
		return true, nil
	}

	// Content - Number of words (space separated)
	if !h.Options.VHostIgnoreNumberOfWords && httpresp1.Words != httpresp2.Words {
		return true, nil
	}

	// Content - Number of lines (newline separated)
	if !h.Options.VHostIgnoreNumberOfLines && httpresp1.Lines != httpresp2.Lines {
		return true, nil
	}

	// Similarity Ratio - if similarity is under threshold we consider it a valid vHost
	if int(strsim.Compare(httpresp1.Raw, httpresp2.Raw)*simMultiplier) <= h.Options.VHostSimilarityRatio {
		return true, nil
	}

	return false, nil
}
