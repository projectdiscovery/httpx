<h1 align="center">
  <img src="static/httpx-logo.png" alt="httpx" width="200px">
  <br>
</h1>



<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/httpx"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/httpx"></a>
<a href="https://github.com/projectdiscovery/httpx/releases"><img src="https://img.shields.io/github/release/projectdiscovery/httpx"></a>
<a href="https://hub.docker.com/r/projectdiscovery/httpx"><img src="https://img.shields.io/docker/pulls/projectdiscovery/httpx.svg"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation-instructions">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="https://docs.projectdiscovery.io/tools/httpx/">Documentation</a> •
  <a href="#notes">Notes</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


`httpx` is a fast and multi-purpose HTTP toolkit that allows running multiple probes using the [retryablehttp](https://github.com/projectdiscovery/retryablehttp-go) library. It is designed to maintain result reliability with an increased number of threads.

# Features

<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/135731750-4c1d38b1-bd2a-40f9-88e9-3c4b9f6da378.png" alt="httpx" width="700px">
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And fully configurable flags to probe multiple elements.
 - Supports multiple HTTP based probings.
 - Smart auto fallback from https to http as default. 
 - Supports hosts, URLs and CIDR as input.
 - Handles edge cases doing retries, backoffs etc for handling WAFs.

### Supported probes

| Probes          | Default check | Probes         | Default check |
|-----------------|---------------|----------------|---------------|
| URL             | true          | IP             | true          |
| Title           | true          | CNAME          | true          |
| Status Code     | true          | Raw HTTP       | false         |
| Content Length  | true          | HTTP2          | false         |
| TLS Certificate | true          | HTTP Pipeline  | false         |
| CSP Header      | true          | Virtual host   | false         |
| Line Count      | true          | Word Count     | true          |
| Location Header | true          | CDN            | false         |
| Web Server      | true          | Paths          | false         |
| Web Socket      | true          | Ports          | false         |
| Response Time   | true          | Request Method | true          |
| Favicon Hash    | false         | Probe  Status  | false         |
| Body Hash       | true          | Header  Hash   | true          |
| Redirect chain  | false         | URL Scheme     | true          |
| JARM Hash       | false         | ASN            | false         |

# Installation Instructions

`httpx` requires **go1.21** to install successfully. Run the following command to get the repo:

```sh
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

To learn more about installing httpx, see https://docs.projectdiscovery.io/tools/httpx/install.

| :exclamation:  **Disclaimer**  |
|---------------------------------|
| **This project is in active development**. Expect breaking changes with releases. Review the changelog before updating. |
| This project was primarily built to be used as a standalone CLI tool. **Running it as a service may pose security risks.** It's recommended to use with caution and additional security measures. |

# Usage

```sh
httpx -h
```

This will display help for the tool. Here are all the switches it supports.


```console
Usage:
  ./httpx [flags]

Flags:
INPUT:
   -l, -list string      input file containing list of hosts to process
   -rr, -request string  file containing raw request
   -u, -target string[]  input target host(s) to probe

PROBES:
   -sc, -status-code     display response status-code
   -cl, -content-length  display response content-length
   -ct, -content-type    display response content-type
   -location             display response redirect location
   -favicon              display mmh3 hash for '/favicon.ico' file
   -hash string          display response body hash (supported: md5,mmh3,simhash,sha1,sha256,sha512)
   -jarm                 display jarm fingerprint hash
   -rt, -response-time   display response time
   -lc, -line-count      display response body line count
   -wc, -word-count      display response body word count
   -title                display page title
   -bp, -body-preview    display first N characters of response body (default 100)
   -server, -web-server  display server name
   -td, -tech-detect     display technology in use based on wappalyzer dataset
   -method               display http request method
   -websocket            display server using websocket
   -ip                   display host ip
   -cname                display host cname
   -asn                  display host asn information
   -cdn                  display cdn/waf in use
   -probe                display probe status

HEADLESS:
   -ss, -screenshot                 enable saving screenshot of the page using headless browser
   -system-chrome                   enable using local installed chrome for screenshot
   -ho, -headless-options string[]  start headless chrome with additional options
   -esb, -exclude-screenshot-bytes  enable excluding screenshot bytes from json output
   -ehb, -exclude-headless-body     enable excluding headless header from json output
   -st, -screenshot-timeout int     set timeout for screenshot in seconds (default 10)

MATCHERS:
   -mc, -match-code string            match response with specified status code (-mc 200,302)
   -ml, -match-length string          match response with specified content length (-ml 100,102)
   -mlc, -match-line-count string     match response body with specified line count (-mlc 423,532)
   -mwc, -match-word-count string     match response body with specified word count (-mwc 43,55)
   -mfc, -match-favicon string[]      match response with specified favicon hash (-mfc 1494302000)
   -ms, -match-string string          match response with specified string (-ms admin)
   -mr, -match-regex string           match response with specified regex (-mr admin)
   -mcdn, -match-cdn string[]         match host with specified cdn provider (cloudfront, fastly, google, leaseweb, stackpath)
   -mrt, -match-response-time string  match response with specified response time in seconds (-mrt '< 1')
   -mdc, -match-condition string      match response with dsl expression condition

EXTRACTOR:
   -er, -extract-regex string[]   display response content with matched regex
   -ep, -extract-preset string[]  display response content matched by a pre-defined regex (url,ipv4,mail)

FILTERS:
   -fc, -filter-code string            filter response with specified status code (-fc 403,401)
   -fep, -filter-error-page            filter response with ML based error page detection
   -fl, -filter-length string          filter response with specified content length (-fl 23,33)
   -flc, -filter-line-count string     filter response body with specified line count (-flc 423,532)
   -fwc, -filter-word-count string     filter response body with specified word count (-fwc 423,532)
   -ffc, -filter-favicon string[]      filter response with specified favicon hash (-ffc 1494302000)
   -fs, -filter-string string          filter response with specified string (-fs admin)
   -fe, -filter-regex string           filter response with specified regex (-fe admin)
   -fcdn, -filter-cdn string[]         filter host with specified cdn provider (cloudfront, fastly, google, leaseweb, stackpath)
   -frt, -filter-response-time string  filter response with specified response time in seconds (-frt '> 1')
   -fdc, -filter-condition string      filter response with dsl expression condition
   -strip                              strips all tags in response. supported formats: html,xml (default html)

RATE-LIMIT:
   -t, -threads int              number of threads to use (default 50)
   -rl, -rate-limit int          maximum requests to send per second (default 150)
   -rlm, -rate-limit-minute int  maximum number of requests to send per minute

MISCELLANEOUS:
   -pa, -probe-all-ips        probe all the ips associated with same host
   -p, -ports string[]        ports to probe (nmap syntax: eg http:1,2-10,11,https:80)
   -path string               path or list of paths to probe (comma-separated, file)
   -tls-probe                 send http probes on the extracted TLS domains (dns_name)
   -csp-probe                 send http probes on the extracted CSP domains
   -tls-grab                  perform TLS(SSL) data grabbing
   -pipeline                  probe and display server supporting HTTP1.1 pipeline
   -http2                     probe and display server supporting HTTP2
   -vhost                     probe and display server supporting VHOST
   -ldv, -list-dsl-variables  list json output field keys name that support dsl matcher/filter

UPDATE:
   -up, -update                 update httpx to latest version
   -duc, -disable-update-check  disable automatic httpx update check

OUTPUT:
   -o, -output string                  file to write output results
   -oa, -output-all                    filename to write output results in all formats
   -sr, -store-response                store http response to output directory
   -srd, -store-response-dir string    store http response to custom directory
   -csv                                store output in csv format
   -csvo, -csv-output-encoding string  define output encoding
   -j, -json                           store output in JSONL(ines) format
   -irh, -include-response-header      include http response (headers) in JSON output (-json only)
   -irr, -include-response             include http request/response (headers + body) in JSON output (-json only)
   -irrb, -include-response-base64     include base64 encoded http request/response in JSON output (-json only)
   -include-chain                      include redirect http chain in JSON output (-json only)
   -store-chain                        include http redirect chain in responses (-sr only)
   -svrc, -store-vision-recon-cluster  include visual recon clusters (-ss and -sr only)

CONFIGURATIONS:
   -config string                path to the httpx configuration file (default $HOME/.config/httpx/config.yaml)
   -r, -resolvers string[]       list of custom resolver (file or comma separated)
   -allow string[]               allowed list of IP/CIDR's to process (file or comma separated)
   -deny string[]                denied list of IP/CIDR's to process (file or comma separated)
   -sni, -sni-name string        custom TLS SNI name
   -random-agent                 enable Random User-Agent to use (default true)
   -H, -header string[]          custom http headers to send with request
   -http-proxy, -proxy string    http proxy to use (eg http://127.0.0.1:8080)
   -unsafe                       send raw requests skipping golang normalization
   -resume                       resume scan using resume.cfg
   -fr, -follow-redirects        follow http redirects
   -maxr, -max-redirects int     max number of redirects to follow per host (default 10)
   -fhr, -follow-host-redirects  follow redirects on the same host
   -rhsts, -respect-hsts         respect HSTS response headers for redirect requests
   -vhost-input                  get a list of vhosts as input
   -x string                     request methods to probe, use 'all' to probe all HTTP methods
   -body string                  post body to include in http request
   -s, -stream                   stream mode - start elaborating input targets without sorting
   -sd, -skip-dedupe             disable dedupe input items (only used with stream mode)
   -ldp, -leave-default-ports    leave default http/https ports in host header (eg. http://host:80 - https://host:443
   -ztls                         use ztls library with autofallback to standard one for tls13
   -no-decode                    avoid decoding body
   -tlsi, -tls-impersonate       enable experimental client hello (ja3) tls randomization
   -no-stdin                     Disable Stdin processing

DEBUG:
   -health-check, -hc        run diagnostic check up
   -debug                    display request/response content in cli
   -debug-req                display request content in cli
   -debug-resp               display response content in cli
   -version                  display httpx version
   -stats                    display scan statistic
   -profile-mem string       optional httpx memory profile dump file
   -silent                   silent mode
   -v, -verbose              verbose mode
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default: 5)
   -nc, -no-color            disable colors in cli output

OPTIMIZATIONS:
   -nf, -no-fallback                  display both probed protocol (HTTPS and HTTP)
   -nfs, -no-fallback-scheme          probe with protocol scheme specified in input 
   -maxhr, -max-host-error int        max error count per host before skipping remaining path/s (default 30)
   -e, -exclude string[]              exclude host matching specified filter ('cdn', 'private-ips', cidr, ip, regex)
   -retries int                       number of retries
   -timeout int                       timeout in seconds (default 10)
   -delay value                       duration between each http request (eg: 200ms, 1s) (default -1ns)
   -rsts, -response-size-to-save int  max response size to save in bytes (default 2147483647)
   -rstr, -response-size-to-read int  max response size to read in bytes (default 2147483647)
```

# Running httpx

For details about running httpx, see https://docs.projectdiscovery.io/tools/httpx/running.

### Using `httpx` as a library
`httpx` can be used as a library by creating an instance of the `Option` struct and populating it with the same options that would be specified via CLI. Once validated, the struct should be passed to a runner instance (to be closed at the end of the program) and the `RunEnumeration` method should be called. A minimal example of how to do it is in the [examples](examples/) folder

# Notes

- As default, `httpx` probe with **HTTPS** scheme and fall-back to **HTTP** only if **HTTPS** is not reachable.
- The `-no-fallback` flag can be used to probe and display both **HTTP** and **HTTPS** result.
- Custom scheme for ports can be defined, for example `-ports http:443,http:80,https:8443`
- Custom resolver supports multiple protocol (**doh|tcp|udp**) in form of `protocol:resolver:port` (e.g. `udp:127.0.0.1:53`)
- The following flags should be used for specific use cases instead of running them as default with other probes:
   - `-ports`
   - `-path`
   - `-vhost`
   - `-screenshot`
   - `-csp-probe`
   - `-tls-probe`
   - `-favicon`
   - `-http2`
   - `-pipeline`
   - `-tls-impersonate`


# Acknowledgement

Probing feature is inspired by [@tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) work ❤️


--------

<div align="center">

`httpx` is made with 💙 by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE.md).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>
