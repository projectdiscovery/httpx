<h1 align="center">
  <img src="static/httpx-logo.png" alt="httpx" width="200px"></a>
  <br>
</h1>



<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://github.com/projectdiscovery/httpx/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
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

<h1 align="left">
  <img src="https://user-images.githubusercontent.com/8293321/117307789-8129d400-ae9e-11eb-8bb8-57fc7410b9ef.png" alt="httpx" width="700px"></a>
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And fully configurable flags to probe mutiple elements.
 - Supports multiple HTTP based probings.
 - Smart auto fallback from https to http as default. 
 - Supports hosts, URLs and CIDR as input.
 - Handles edge cases doing retries, backoffs etc for handling WAFs.

### Supported probes:-

| Probes             | Default check   | Probes             | Default check   |
|--------------------|-----------------|--------------------|-----------------|
| URL                | true            | IP                 | true            |
| Title              | true            | CNAME              | true            |
| Status Code        | true            | Raw HTTP           | false           |
| Content Length     | true            | HTTP2              | false           |
| TLS Certificate    | true            | HTTP 1.1 Pipeline  | false           |
| CSP Header         | true            | Virtual host       | false           |
| Location Header    | true            | CDN                | false           |
| Web Server         | true            | Path               | false           |
| Web Socket         | true            | Ports              | false           |
| Response Time      | true            | Request method     | false           |


# Installation Instructions

httpx requires **go1.14+** to install successfully. Run the following command to get the repo - 

```sh
GO111MODULE=on go get -v github.com/projectdiscovery/httpx/cmd/httpx
```

# Usage

```sh
httpx -h
```

This will display help for the tool. Here are all the switches it supports.

<details>
<summary> 👉 httpx help menu 👈</summary>

```
Usage of ./httpx:

  -H value
      Custom Header
  -allow value
      Allowlist ip/cidr
  -body string
      Request Body
  -cdn
      Check if domain's ip belongs to known CDN (akamai, cloudflare, ..)
  -cname
      Output first cname
  -content-length
      Extracts content length
  -content-type
      Extracts content-type
  -csp-probe
      Send HTTP probes on the extracted CSP domains
  -debug
      Debug mode
  -deny value
      Denylist ip/cidr
  -extract-regex string
      Extract Regex
  -fc string
      Filter status code
  -filter-regex string
      Filter Regex
  -filter-string string
      Filter String
  -fl string
      Filter content length
  -follow-host-redirects
      Only follow redirects on the same host
  -follow-redirects
      Follow Redirects
  -http-proxy string
      HTTP Proxy, eg http://127.0.0.1:8080
  -http2
      HTTP2 probe
  -include-chain
      Show Raw HTTP Chain In Output (-json only)
  -include-response
      Show Raw HTTP Response In Output (-json only)
  -ip
      Output target ip
  -json
      JSON Output
  -l string
      File containing domains
  -location
      Extracts location header
  -match-regex string
      Match Regex
  -match-string string
      Match string
  -max-response-body-size int
      Maximum response body size (default 2147483647)
  -mc string
      Match status code
  -method
      Output method
  -ml string
      Match content length
  -no-color
      No Color
  -no-fallback
      If HTTPS on port 443 is successful on default configuration, probes also port 80 for HTTP
  -o string
      File to write output to (optional)
  -path string
      Request path/file (example '/api')
  -paths string
      Command separated paths or file containing one path per line (example '/api/v1,/apiv2')
  -pipeline
      HTTP1.1 Pipeline
  -ports value
      ports range (nmap syntax: eg 1,2-10,11)
  -random-agent
      Use randomly selected HTTP User-Agent header value
  -request string
      File containing raw request
  -response-in-json
      Show Raw HTTP Response In Output (-json only) (deprecated)
  -response-time
      Output the response time
  -retries int
      Number of retries
  -silent
      Silent mode
  -sr
      Save response to file (default 'output')
  -srd string
      Save response directory (default "output")
  -stats
      Enable statistic on keypress (terminal may become unresponsive till the end)
  -status-code
      Extracts status code
  -store-chain
      Save chain to file (default 'output')
  -tech-detect
      Perform wappalyzer based technology detection
  -threads int
      Number of threads (default 50)
  -timeout int
      Timeout in seconds (default 5)
  -title
      Extracts title
  -tls-grab
      Perform TLS data grabbing
  -tls-probe
      Send HTTP probes on the extracted TLS domains
  -unsafe
      Send raw requests skipping golang normalization
  -verbose
      Verbose Mode
  -version
      Show version of httpx
  -vhost
      Check for VHOSTs
  -vhost-input
      Get a list of vhosts as input
  -web-server
      Extracts server header
  -websocket
      Prints out if the server exposes a websocket
  -x string
      Request Methods, use ALL to check all verbs ()
```
</details>

# Running httpX

### Running httpx with stdin  

This will run the tool against all the hosts and subdomains in `hosts.txt` and returns URLs running HTTP webserver. 

```sh
▶ cat hosts.txt | httpx 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|   v1.0  
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

### Running httpx with file input  

This will run the tool against all the hosts and subdomains in `hosts.txt` and returns URLs running HTTP webserver.

```sh
▶ httpx -l hosts.txt -silent

https://docs.hackerone.com
https://mta-sts.hackerone.com
https://mta-sts.managed.hackerone.com
https://mta-sts.forwarding.hackerone.com
https://www.hackerone.com
https://resources.hackerone.com
https://api.hackerone.com
https://support.hackerone.com
```

### Running httpx with CIDR input   

```sh
▶ echo 173.0.84.0/24 | httpx -silent

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


### Running httpx with subfinder


```sh
▶ subfinder -d hackerone.com | httpx -title -tech-detect -status-code -follow-redirects

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   /
 / / / / /_/ /_/ /_/ /   |
/_/ /_/\__/\__/ .___/_/|_|
             /_/              v1.0.6

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

# 📋 Notes

- As default, **httpx** checks for `HTTPS` probe and fall-back to `HTTP` only if `HTTPS` is not reachable.
- For printing both HTTP/HTTPS results, `no-fallback` flag can be used.
- Custom scheme for ports can be defined, for example `-ports http:443,http:80,https:8443`
- `vhost`, `http2`, `pipeline`, `ports`, `csp-probe`, `tls-probe` and `path` are unique flag with different probes.
- Unique flags should be used for specific use cases instead of running them as default with other flags.
- When using `json` flag, all the information (default probes) included in the JSON output.


# Thanks

httpx is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/httpx/blob/master/THANKS.md)** file for more details. Do also check out these similar awesome projects that may fit in your workflow:

Probing feature is inspired by [@tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) work :heart:
