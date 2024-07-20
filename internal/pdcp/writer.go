package pdcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/projectdiscovery/retryablehttp-go"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/conversion"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
	unitutils "github.com/projectdiscovery/utils/unit"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
)

const (
	uploadEndpoint = "/v1/assets"
	appendEndpoint = "/v1/assets/%s/contents"
	flushTimer     = time.Minute
	MaxChunkSize   = 4 * unitutils.Mega // 4 MB
	xidRe          = `^[a-z0-9]{20}$`
	teamIDHeader   = "X-Team-Id"
)

var (
	xidRegex = regexp.MustCompile(xidRe)
	// teamID if given
	teamID = env.GetEnvOrDefault("PDCP_TEAM_ID", "")
	// EnableeUpload if set to true enables the upload feature
	HideAutoSaveMsg   = env.GetEnvOrDefault("DISABLE_CLOUD_UPLOAD_WRN", false)
	EnableCloudUpload = env.GetEnvOrDefault("ENABLE_CLOUD_UPLOAD", false)
)

// UploadWriter is a writer that uploads its output to pdcp
// server to enable web dashboard and more
type UploadWriter struct {
	creds          *pdcpauth.PDCPCredentials
	uploadURL      *url.URL
	client         *retryablehttp.Client
	done           chan struct{}
	data           chan runner.Result
	assetGroupID   string
	assetGroupName string
	counter        atomic.Int32
	closed         atomic.Bool
}

// NewUploadWriterCallback creates a new upload writer callback
// which when enabled periodically uploads the results to pdcp assets dashboard
func NewUploadWriterCallback(ctx context.Context, creds *pdcpauth.PDCPCredentials) (*UploadWriter, error) {
	if creds == nil {
		return nil, fmt.Errorf("no credentials provided")
	}
	u := &UploadWriter{
		creds: creds,
		done:  make(chan struct{}, 1),
		data:  make(chan runner.Result, 8), // default buffer size
	}
	var err error
	tmp, err := urlutil.Parse(creds.Server)
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not parse server url")
	}
	tmp.Path = uploadEndpoint
	tmp.Update()
	u.uploadURL = tmp.URL

	// create http client
	opts := retryablehttp.DefaultOptionsSingle
	opts.NoAdjustTimeout = true
	opts.Timeout = time.Duration(3) * time.Minute
	u.client = retryablehttp.NewClient(opts)
	// start auto commit
	// upload every 1 minute or when buffer is full
	go u.autoCommit(ctx)
	return u, nil
}

// GetWriterCallback returns the writer callback
func (u *UploadWriter) GetWriterCallback() runner.OnResultCallback {
	return func(r runner.Result) {
		if r.Err != nil {
			return
		}
		u.data <- r
	}
}

// SetAssetID sets the scan id for the upload writer
func (u *UploadWriter) SetAssetID(id string) error {
	if !xidRegex.MatchString(id) {
		return fmt.Errorf("invalid asset id provided")
	}
	u.assetGroupID = id
	return nil
}

// SetAssetGroupName sets the scan name for the upload writer
func (u *UploadWriter) SetAssetGroupName(name string) {
	u.assetGroupName = name
}

func (u *UploadWriter) autoCommit(ctx context.Context) {
	// wait for context to be done
	defer func() {
		u.done <- struct{}{}
		close(u.done)
		// if no scanid is generated no results were uploaded
		if u.assetGroupID == "" {
			gologger.Verbose().Msgf("UI dashboard setup skipped, no results found to upload")
		} else {
			gologger.Info().Msgf("Found %v results, View found results in dashboard : %v", u.counter.Load(), getAssetsDashBoardURL(u.assetGroupID))
		}
	}()
	// temporary buffer to store the results
	buff := &bytes.Buffer{}
	ticker := time.NewTicker(flushTimer)

	for {
		select {
		case <-ctx.Done():
			// flush before exit
			if buff.Len() > 0 {
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
				}
			}
			return
		case <-ticker.C:
			// flush the buffer
			if buff.Len() > 0 {
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
				}
			}
		case res, ok := <-u.data:
			if !ok {
				if buff.Len() > 0 {
					if err := u.uploadChunk(buff); err != nil {
						gologger.Error().Msgf("Failed to upload scan results on cloud: %v", err)
					}
				}
				return
			}
			if res.Err != nil {
				// skip we don't care
				continue
			}
			lineBytes, err := json.Marshal(res)
			if err != nil {
				gologger.Error().Msgf("Failed to marshal result: %v", err)
				continue
			}
			u.counter.Add(1)
			line := conversion.String(lineBytes)
			if buff.Len()+len(line) > MaxChunkSize {
				// flush existing buffer
				if err := u.uploadChunk(buff); err != nil {
					gologger.Error().Msgf("Failed to upload asset results on cloud: %v", err)
				}
			} else {
				buff.WriteString(line)
				buff.WriteString("\n")
			}
		}
	}
}

// uploadChunk uploads a chunk of data to the server
func (u *UploadWriter) uploadChunk(buff *bytes.Buffer) error {
	if err := u.upload(buff.Bytes()); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not upload chunk")
	}
	// if successful, reset the buffer
	buff.Reset()
	// log in verbose mode
	gologger.Warning().Msgf("Uploaded results chunk, you can view assets at %v", getAssetsDashBoardURL(u.assetGroupID))
	return nil
}

func (u *UploadWriter) upload(data []byte) error {
	req, err := u.getRequest(data)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not create upload request")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not upload results")
	}
	defer resp.Body.Close()
	bin, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not get id from response")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("could not upload results got status code %v on %v", resp.StatusCode, resp.Request.URL.String())
	}
	var uploadResp uploadResponse
	if err := json.Unmarshal(bin, &uploadResp); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not unmarshal response got %v", string(bin))
	}
	if uploadResp.ID != "" && u.assetGroupID == "" {
		u.assetGroupID = uploadResp.ID
	}
	return nil
}

// getRequest returns a new request for upload
// if scanID is not provided create new scan by uploading the data
// if scanID is provided append the data to existing scan
func (u *UploadWriter) getRequest(bin []byte) (*retryablehttp.Request, error) {
	var method, url string

	if u.assetGroupID == "" {
		u.uploadURL.Path = uploadEndpoint
		method = http.MethodPost
		url = u.uploadURL.String()
	} else {
		u.uploadURL.Path = fmt.Sprintf(appendEndpoint, u.assetGroupID)
		method = http.MethodPatch
		url = u.uploadURL.String()
	}
	req, err := retryablehttp.NewRequest(method, url, bytes.NewReader(bin))
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("could not create cloud upload request")
	}
	// add pdtm meta params
	req.URL.Params.Merge(updateutils.GetpdtmParams(runner.Version))
	// if it is upload endpoint also include name if it exists
	if u.assetGroupName != "" && req.URL.Path == uploadEndpoint {
		req.URL.Params.Add("name", u.assetGroupName)
	}
	req.URL.Update()

	req.Header.Set(pdcpauth.ApiKeyHeaderName, u.creds.APIKey)
	if teamID != "" {
		req.Header.Set(teamIDHeader, teamID)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// Close closes the upload writer
func (u *UploadWriter) Close() {
	if !u.closed.Load() {
		// protect to avoid channel closed twice error
		close(u.data)
		u.closed.Store(true)
	}
	<-u.done
}
