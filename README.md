<h1 align="left">
  <img src="static/httpx-logo.png" alt="httpx" width="200px"></a>
  <br>
</h1>

[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Go Report Card](https://goreportcard.com/badge/github.com/projectdiscovery/httpx)](https://goreportcard.com/report/github.com/projectdiscovery/httpx)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/projectdiscovery/httpx/issues)

httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using [retryablehttp-go library](https://github.com/projectdiscovery/retryablehttp-go) library. 

# Resources
- [Resources](#resources)
- [Features](#features)
- [Usage](#usage)
- [Installation Instructions](#installation-instructions)
    - [From Binary](#from-binary)
    - [From Source](#from-source)
- [Running httpx](#running-httpx)
    - [Running httpx with a single template.](#running-httpx)
- [Thanks](#thanks)

 # Features

<h1 align="left">
  <img src="static/httpx-run.png" alt="httpx" width="700px"></a>
  <br>
</h1>

 - Simple and modular code base making it easy to contribute.
 - Fast And fully configurable flags to probe mutiple elements
 - Supports vhost, urls, ports, title, content-length, status-code, response-body probbing. 
 - Handles edge cases doing retries, backoffs etc for handling WAFs.

# Usage

```bash
httpx -h
```

This will display help for the tool. Here are all the switches it supports.

| Flag               | Description                                           | Example                                            |
|------------------- |-------------------------------------------------------|----------------------------------------------------|
| -H                 | Custom Header input                                   | httpx -H 'x-bug-bounty: hacker'                    |
| -follow-redirects  | Follow URL redirects (default false)                  | httpx -follow-redirects                            |
| -http-proxy        | URL of the proxy server                               | httpx -http-proxy hxxp://proxy-host:80             |
| -l                 | File to save output result (optional)                 | httpx -o output.txt                                |
| -no-color          | Disable colors in the output.                         | httpx -no-color                                    |
| -o                 | File to save output result (optional)                 | httpx -o output.txt                                |
| -json              | Prints all the probes in JSON format (default false)  | httpx -json                                        |
| -vhost             | Probes to detect vhost from list of subdomains        | httpx -vhost                                       |
| -threads           | Number of threads (default 50)                        | httpx - threads 100                                |
| -ports             | Ports ranges to probe (nmap syntax: eg 1,2-10,11)     | httpx -ports 80,443,100-200                        |
| -title             | Prints title of page if avaiable                      | httpx -title                                       |
| -content-length    | Prints content length in the output                   | httpx -content-length                              |
| -status-code       | Prints status code in the output                      | httpx -status-code                                 |
| -store-response    | Store response as domain.txt                          | httpx -store-response                              |
| -store-response-dir| Directory to store response (default current path)    | httpx -store-response-dir output                   | 
| -retries           | Number of retries                                     | httpx -retries                                     |
| -silent            | Prints only results in the output                     | httpx -silent                                      |
| -timeout           | Timeout in seconds (default 5)                        | httpx -timeout 10                                  |
| -verbose           | Verbose Mode                                          | httpx -verbose                                     |
| -version           | Prints current version of the httpx                   | httpx -version                                     |
| -x                 | Request Method (default 'GET')                        | httpx -x HEAD                                      |


# Installation Instructions


### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/projectdiscovery/httpx/releases/) page. Extract them using tar, move it to your `$PATH`and you're ready to go.

```bash
> tar -xzvf httpx-linux-amd64.tar.gz
> mv httpx-linux-amd64 /usr/bin/httpx
> httpx -h
```

### From Source

httpx requires go1.13+ to install successfully. Run the following command to get the repo - 

```bash
> GO111MODULE=on go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
```

In order to update the tool, you can use -u flag with `go get` command.

# Running httpX to probe `2967` hosts

```bash 
> chaos -d oath.cloud -count -silent 
2967

> time chaos -d oath.cloud -silent | httpx -status-code -content-length -title -store-response -threads 100 -json | wc 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/            

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
196

real	0m52.159s
user	0m4.084s
sys	0m3.880s
```

### Running httpx with stnin  

This will run the tool against all the hosts in `urls.txt` and returns the matched results. 

```bash
> cat hosts.txt | httpx 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
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

This will run the tool against all the hosts in `urls.txt` and returns the matched results. 

```bash
> httpx -l hosts.txt

root@b0x:~/httpx# httpx -l hosts.txt 

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/            

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
https://docs.hackerone.com
https://mta-sts.hackerone.com
https://mta-sts.managed.hackerone.com
https://mta-sts.forwarding.hackerone.com
https://www.hackerone.com
https://resources.hackerone.com
https://api.hackerone.com
https://support.hackerone.com
```


### Using httpX with subfinder/chaos and any other similar tool.


```bash
> subfinder -d hackerone.com -silent | httpx httpx -title -content-length -status-code


    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/            

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
https://mta-sts.forwarding.hackerone.com [404] [9339] [Page not found · GitHub Pages]
https://mta-sts.hackerone.com [404] [9339] [Page not found · GitHub Pages]
https://mta-sts.managed.hackerone.com [404] [9339] [Page not found · GitHub Pages]
https://docs.hackerone.com [200] [65444] [HackerOne Platform Documentation]
https://www.hackerone.com [200] [54166] [Bug Bounty - Hacker Powered Security Testing | HackerOne]
https://support.hackerone.com [301] [489] []
https://api.hackerone.com [200] [7791] [HackerOne API]
https://hackerone.com [301] [92] []
https://resources.hackerone.com [301] [0] []
```

### Running httpX with json output

```bash
> chaos -d hackerone.com -silent | httpx -json

    __    __  __       _  __
   / /_  / /_/ /_____ | |/ /
  / __ \/ __/ __/ __ \|   / 
 / / / / /_/ /_/ /_/ /   |  
/_/ /_/\__/\__/ .___/_/|_|  
             /_/            

		projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions
[WRN] Developers assume no liability and are not responsible for any misuse or damage.

{"url":"https://mta-sts.forwarding.hackerone.com","content-length":9339,"status-code":404,"title":"","error":null,"vhost":false}
{"url":"https://mta-sts.hackerone.com","content-length":9339,"status-code":404,"title":"","error":null,"vhost":false}
{"url":"https://docs.hackerone.com","content-length":65444,"status-code":200,"title":"","error":null,"vhost":false}
{"url":"https://mta-sts.managed.hackerone.com","content-length":9339,"status-code":404,"title":"","error":null,"vhost":false}
{"url":"https://support.hackerone.com","content-length":489,"status-code":301,"title":"","error":null,"vhost":false}
{"url":"https://resources.hackerone.com","content-length":0,"status-code":301,"title":"","error":null,"vhost":false}
{"url":"https://api.hackerone.com","content-length":7791,"status-code":200,"title":"","error":null,"vhost":false}
{"url":"https://www.hackerone.com","content-length":54166,"status-code":200,"title":"","error":null,"vhost":false}

```

You can simply use `jq` to filter out the json results as per your interest. 

## Todo

- [ ] Adding support to probe [http smuggling](https://portswigger.net/web-security/request-smuggling)


# Thanks

httpX is made with 🖤 by the [projectdiscovery](https://projectdiscovery.io) team. Community contributions have made the project what it is. See the **[Thanks.md](https://github.com/projectdiscovery/httpx/blob/master/THANKS.md)** file for more details. Do also check out these similar awesome projects that may fit in your workflow:

[https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe)</br>


