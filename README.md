<h1 align="center">
  <img src="static/httpx-logo.png" alt="httpx" width="200px"></a>
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
  <a href="#running-httpx">Running httpx</a> •
  <a href="#-notes">Notes</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>


httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using [retryablehttp](https://github.com/projectdiscovery/retryablehttp-go) library, it is designed to maintain the result reliability with increased threads.

# Features

<h1 align="center">
  <img src="https://user-images.githubusercontent.com/8293321/135731750-4c1d38b1-bd2a-40f9-88e9-3c4b9f6da378.png" alt="httpx" width="700px"></a>
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And fully configurable flags to probe multiple elements.
 - Supports multiple HTTP based probings.
 - Smart auto fallback from https to http as default. 
 - Supports hosts, URLs and CIDR as input.
 - Handles edge cases doing retries, backoffs etc for handling WAFs.

### Supported probes:-

| Probes          | Default check | Probes            | Default check |
| --------------- | ------------- | ----------------- | ------------- |
| URL             | true          | IP                | true          |
| Title           | true          | CNAME             | true          |
| Status Code     | true          | Raw HTTP          | false         |
| Content Length  | true          | HTTP2             | false         |
| TLS Certificate | true          | HTTP Pipeline     | false         |
| CSP Header      | true          | Virtual host      | false         |
| Line Count      | true          | Word Count        | true          |
| Location Header | true          | CDN               | false         |
| Web Server      | true          | Paths             | false         |
| Web Socket      | true          | Ports             | false         |
| Response Time   | true          | Request Method    | true          |
| Favicon Hash    | false         | Probe  Status     | false         |
| Body Hash       | true          | Header  Hash      | true          |
| Redirect chain  | false         | URL Scheme        | true          |


# Installation Instructions

httpx requires **go1.17** to install successfully. Run the following command to get the repo - 

```sh
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

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
   -l, -list string  Input file containing list of hosts to process
   -request string   File containing raw request

PROBES:
   -sc, -status-code     Display Status Code
   -td, -tech-detect     Display wappalyzer based technology detection
   -cl, -content-length  Display Content-Length
   -lc, -line-count      Display Response body line count
   -wc, -word-count      Display Response body word count
   -server, -web-server  Display Server header
   -ct, -content-type    Display Content-Type header
   -rt, -response-time   Display the response time
   -title                Display page title
   -location             Display Location header
   -method               Display Request method
   -websocket            Display server using websocket
   -ip                   Display Host IP
   -cname                Display Host cname
   -cdn                  Display if CDN in use
   -probe                Display probe status

MATCHERS:
   -mc, -match-code string     Match response with given status code (-mc 200,302)
   -ml, -match-length string   Match response with given content length (-ml 100,102)
   -ms, -match-string string   Match response with given string
   -mr, -match-regex string    Match response with specific regex
   -er, -extract-regex string  Display response content with matched regex
   -mlc, -match-line-count string  Match Response body line count
   -mwc, -match-word-count string  Match Response body word count
   -mfc, -match-favicon string[]   Match response with specific favicon

FILTERS:
   -fc, -filter-code string    Filter response with given status code (-fc 403,401)
   -fl, -filter-length string  Filter response with given content length (-fl 23,33)
   -fs, -filter-string string  Filter response with specific string
   -fe, -filter-regex string   Filter response with specific regex
   -flc, -filter-line-count string  Filter Response body line count
   -fwc, -filter-word-count string  Filter Response body word count
   -ffc, -filter-favicon string[]   Filter response with specific favicon

RATE-LIMIT:
   -t, -threads int      Number of threads (default 50)
   -rl, -rate-limit int  Maximum requests to send per second (default 150)

MISCELLANEOUS:
   -favicon             Probes for favicon ("favicon.ico" as path) and display phythonic hash
   -tls-grab            Perform TLS(SSL) data grabbing
   -tls-probe           Send HTTP probes on the extracted TLS domains
   -csp-probe           Send HTTP probes on the extracted CSP domains
   -pipeline            HTTP1.1 Pipeline probe
   -http2               HTTP2 probe
   -vhost               VHOST Probe
   -p, -ports string[]  Port to scan (nmap syntax: eg 1,2-10,11)
   -path string         File or comma separated paths to request
   -paths string        File or comma separated paths to request (deprecated)

OUTPUT:
   -o, -output string                file to write output
   -sr, -store-response              store http response to output directory
   -srd, -store-response-dir string  store http response to custom directory (default "output")
   -csv                              store output in CSV format
   -json                             store output in JSONL(ines) format
   -irr, -include-response           include http request/response in JSON output (-json only)
   -include-chain                    include redirect http chain in JSON output (-json only)
   -store-chain                      include http redirect chain in responses (-sr only)

CONFIGURATIONS:
   -r, -resolvers string[]       List of custom resolvers (file or comma separated)
   -allow string[]               Allowed list of IP/CIDR's to process (file or comma separated)
   -deny string[]                Denied list of IP/CIDR's to process (file or comma separated)
   -random-agent                 Enable Random User-Agent to use (default true)
   -H, -header string[]          Custom Header to send with request
   -http-proxy, -proxy string    HTTP Proxy, eg http://127.0.0.1:8080
   -unsafe                       Send raw requests skipping golang normalization
   -resume                       Resume scan using resume.cfg
   -fr, -follow-redirects        Follow HTTP redirects
   -maxr, -max-redirects int     Max number of redirects to follow per host (default 10)
   -fhr, -follow-host-redirects  Follow redirects on the same host
   -vhost-input                  Get a list of vhosts as input
   -x string                     Request methods to use, use 'all' to probe all HTTP methods
   -body string                  Post body to include in HTTP request
   -s, -stream                   Stream mode - start elaborating input targets without sorting
   -sd, -skip-dedupe             Disable dedupe input items (only used with stream mode)
   -pa, -probe-all-ips           Probe all the ips associated with same host

DEBUG:
   -silent         Silent mode
   -v, -verbose    Verbose mode
   -version        Display version
   -nc, -no-color  Disable color in output
   -debug          Debug mode
   -debug-req      Show all sent requests
   -debug-resp     Show all received responses
   -stats          Display scan statistic

OPTIMIZATIONS:
   -nf, -no-fallback                  Display both probbed protocol (HTTPS and HTTP)
   -nfs, -no-fallback-scheme          Probe with input protocol scheme
   -maxhr, -max-host-error int        Max error count per host before skipping remaining path/s (default 30)
   -ec, -exclude-cdn                  Skip full port scans for CDNs (only checks for 80,443)
   -retries int                       Number of retries
   -timeout int                       Timeout in seconds (default 5)
   -rsts, -response-size-to-save int  Max response size to save in bytes (default 2147483647)
   -rstr, -response-size-to-read int  Max response size to read in bytes (default 2147483647)
```

# Running httpX

### URL Probe

This will run the tool against all the hosts and subdomains in `hosts.txt` and returns URLs running HTTP webserver. 

```console
cat hosts.txt | httpx 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|   v1.1.1  
             /_/            

    projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

https://mta-sts.managed.hackerone.com
https://mta-sts.hackerone.com
https://mta-sts.forwarding.hackerone.com
https://docs.hackerone.com
https://www.hackerone.com
https://resources.hackerone.com
https://api.hackerone.com
https://support.hackerone.com
```

### File Input

This will run the tool with the `probe` flag against all of the hosts in **hosts.txt** and return URLs with probed status.

```console
httpx -list hosts.txt -silent -probe

http://ns.hackerone.com [FAILED]
https://docs.hackerone.com [SUCCESS]
https://mta-sts.hackerone.com [SUCCESS]
https://mta-sts.managed.hackerone.com [SUCCESS]
http://email.hackerone.com [FAILED]
https://mta-sts.forwarding.hackerone.com [SUCCESS]
http://links.hackerone.com [FAILED]
https://api.hackerone.com [SUCCESS]
https://www.hackerone.com [SUCCESS]
http://events.hackerone.com [FAILED]
https://support.hackerone.com [SUCCESS]
https://gslink.hackerone.com [SUCCESS]
http://o1.email.hackerone.com [FAILED]
http://info.hackerone.com [FAILED]
https://resources.hackerone.com [SUCCESS]
http://o2.email.hackerone.com [FAILED]
http://o3.email.hackerone.com [FAILED]
http://go.hackerone.com [FAILED]
http://a.ns.hackerone.com [FAILED]
http://b.ns.hackerone.com [FAILED]
```

### CIDR Input   

```console
echo 173.0.84.0/24 | httpx -silent

https://173.0.84.29
https://173.0.84.43
https://173.0.84.31
https://173.0.84.44
https://173.0.84.12
https://173.0.84.4
https://173.0.84.36
https://173.0.84.45
https://173.0.84.14
https://173.0.84.25
https://173.0.84.46
https://173.0.84.24
https://173.0.84.32
https://173.0.84.9
https://173.0.84.13
https://173.0.84.6
https://173.0.84.16
https://173.0.84.34
```


### Tool Chain


```console
subfinder -d hackerone.com -silent| httpx -title -tech-detect -status-code

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.1

    projectdiscovery.io

Use with caution. You are responsible for your actions
Developers assume no liability and are not responsible for any misuse or damage.
https://mta-sts.managed.hackerone.com [404] [Page not found · GitHub Pages] [Varnish,GitHub Pages,Ruby on Rails]
https://mta-sts.hackerone.com [404] [Page not found · GitHub Pages] [Varnish,GitHub Pages,Ruby on Rails]
https://mta-sts.forwarding.hackerone.com [404] [Page not found · GitHub Pages] [GitHub Pages,Ruby on Rails,Varnish]
https://docs.hackerone.com [200] [HackerOne Platform Documentation] [Ruby on Rails,jsDelivr,Gatsby,React,webpack,Varnish,GitHub Pages]
https://support.hackerone.com [301,302,301,200] [HackerOne] [Cloudflare,Ruby on Rails,Ruby]
https://resources.hackerone.com [301,301,404] [Sorry, no Folders found.]
```

### Favicon Hash


```console
subfinder -d hackerone.com -silent | httpx -favicon

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

      projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
https://docs.hackerone.com/favicon.ico [595148549]
https://hackerone.com/favicon.ico [595148549]
https://mta-sts.managed.hackerone.com/favicon.ico [-1700323260]
https://mta-sts.forwarding.hackerone.com/favicon.ico [-1700323260]
https://support.hackerone.com/favicon.ico [-1279294674]
https://gslink.hackerone.com/favicon.ico [1506877856]
https://resources.hackerone.com/favicon.ico [-1840324437]
https://api.hackerone.com/favicon.ico [566218143]
https://mta-sts.hackerone.com/favicon.ico [-1700323260]
https://www.hackerone.com/favicon.ico [778073381]
```

### Path Probe


```console
httpx -l urls.txt -path /v1/api -sc

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.5

      projectdiscovery.io

Use with caution. You are responsible for your actions.
Developers assume no liability and are not responsible for any misuse or damage.
https://mta-sts.managed.hackerone.com/v1/api [404]
https://mta-sts.hackerone.com/v1/api [404]
https://mta-sts.forwarding.hackerone.com/v1/api [404]
https://docs.hackerone.com/v1/api [404]
https://api.hackerone.com/v1/api [401]
https://hackerone.com/v1/api [302]
https://support.hackerone.com/v1/api [404]
https://resources.hackerone.com/v1/api [301]
https://gslink.hackerone.com/v1/api [404]
http://www.hackerone.com/v1/api [301]
```

### Docker Run

```console
cat sub_domains.txt | docker run -i projectdiscovery/httpx

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.1.2

      projectdiscovery.io

Use with caution. You are responsible for your actions
Developers assume no liability and are not responsible for any misuse or damage.
https://mta-sts.forwarding.hackerone.com
https://mta-sts.hackerone.com
https://mta-sts.managed.hackerone.com
https://www.hackerone.com
https://api.hackerone.com
https://gslink.hackerone.com
https://resources.hackerone.com
https://docs.hackerone.com
https://support.hackerone.com
```


# 📋 Notes

- As default, **httpx** checks for `HTTPS` probe and fall-back to `HTTP` only if `HTTPS` is not reachable.
- For printing both HTTP/HTTPS results, `no-fallback` flag can be used.
- Custom scheme for ports can be defined, for example `-ports http:443,http:80,https:8443`
- `favicon`,`vhost`, `http2`, `pipeline`, `ports`, `csp-probe`, `tls-probe` and `path` are unique flag with different probes.
- Unique flags should be used for specific use cases instead of running them as default with other probes.
- When using `json` flag, all the information (default probes) included in the JSON output.
- Custom resolver supports multiple protocol (**doh|tcp|udp**) in form of `protocol:resolver:port`  (eg **udp:127.0.0.1:53**)
- Invalid custom resolvers/files are ignored.

# Acknowledgement

httpx is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/httpx/blob/master/THANKS.md)** file for more details. Do also check out these similar awesome projects that may fit in your workflow:

Probing feature is inspired by [@tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) work :heart:
