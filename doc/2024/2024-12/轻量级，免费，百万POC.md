#  轻量级，免费，百万POC   
菜狗  富贵安全   2024-12-30 00:38  
  
### Nuclei 是一款现代的高性能漏洞扫描程序，它利用基于 YAML 的简单模板。它使您能够设计模拟真实情况的自定义漏洞检测场景，从而实现零误报。  
- 用于创建和自定义漏洞模板的简单 YAML 格式。  
  
- 由数千名安全专家贡献，以解决流行的漏洞。  
  
- 通过模拟真实世界的步骤来验证漏洞，从而减少误报。  
  
- 超快速的并行扫描处理和请求聚类。  
  
- 集成到 CI/CD 管道中以进行漏洞检测和回归测试。  
  
- 支持多种协议，如 TCP、DNS、HTTP、SSL、WHOIS JavaScript、代码等。  
  
- 与 Jira、Splunk、GitHub、Elastic、GitLab 集成。  
  
### 立即开始  
1. 核 CLI  
  
- 在您的机器上安装 Nuclei。按照此处的安装指南开始安装。此外，我们还提供免费云层，并提供慷慨的每月免费限额：  
  
- 存储并可视化您的漏洞发现  
  
- 编写和管理您的核模板  
  
- 访问最新的原子核模板  
  
- 发现并存储您的目标  
  
### 2. 专业版和企业版  
  
对于安全团队和企业，我们提供基于 Nuclei OSS 构建的云托管服务，该服务经过微调，可帮助您与您的团队和现有工作流程一起持续大规模运行漏洞扫描：  
- 扫描速度提高 50 倍  
  
- 大规模高精度扫描  
  
- 与云服务集成（AWS、GCP、Azure、CloudFlare、Fastly、Terraform、Kubernetes）  
  
- Jira、Slack、Linear、API 和 Webhooks  
  
- 执行和合规报告  
  
- 另外：实时扫描、SAML SSO、SOC 2 兼容平台（具有欧盟和美国托管选项）、共享团队工作区等  
  
- 我们正在不断添加新功能！  
  
- 适用于：渗透测试人员、安全团队和企业  
  
- 如果您的组织规模较大且要求复杂，请注册 Pro或与我们的团队联系。  
  
### 安装  
  
nuclei需要go1.21才能成功安装。运行以下命令获取 repo：  
```
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```  
  
要了解有关安装 nuclei 的更多信息，请参阅https://docs.projectdiscovery.io/tools/nuclei/install。  
### 命令行标志  
  
要显示该工具的所有标志：  
```
nuclei -h
```  
```
Nuclei is a fast, template based vulnerability scanner focusingon extensive configurability, massive extensibility and ease of use.Usage:  ./nuclei [flags]Flags:TARGET:   -u, -target string[]          target URLs/hosts to scan   -l, -list string              path to file containing a list of target URLs/hosts to scan (one per line)   -eh, -exclude-hosts string[]  hosts to exclude to scan from the input list (ip, cidr, hostname)   -resume string                resume scan using resume.cfg (clustering will be disabled)   -sa, -scan-all-ips            scan all the IP's associated with dns record   -iv, -ip-version string[]     IP version to scan of hostname (4,6) - (default 4)TARGET-FORMAT:   -im, -input-mode string        mode of input file (list, burp, jsonl, yaml, openapi, swagger) (default "list")   -ro, -required-only            use only required fields in input format when generating requests   -sfv, -skip-format-validation  skip format validation (like missing vars) when parsing input fileTEMPLATES:   -nt, -new-templates                    run only new templates added in latest nuclei-templates release   -ntv, -new-templates-version string[]  run new templates added in specific version   -as, -automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping   -t, -templates string[]                list of template or template directory to run (comma-separated, file)   -turl, -template-url string[]          template url or list containing template urls to run (comma-separated, file)   -w, -workflows string[]                list of workflow or workflow directory to run (comma-separated, file)   -wurl, -workflow-url string[]          workflow url or list containing workflow urls to run (comma-separated, file)   -validate                              validate the passed templates to nuclei   -nss, -no-strict-syntax                disable strict syntax check on templates   -td, -template-display                 displays the templates content   -tl                                    list all available templates   -tgl                                   list all available tags   -sign                                  signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable   -code                                  enable loading code protocol-based templates   -dut, -disable-unsigned-templates      disable running unsigned templates or templates with mismatched signatureFILTERING:   -a, -author string[]               templates to run based on authors (comma-separated, file)   -tags string[]                     templates to run based on tags (comma-separated, file)   -etags, -exclude-tags string[]     templates to exclude based on tags (comma-separated, file)   -itags, -include-tags string[]     tags to be executed even if they are excluded either by default or configuration   -id, -template-id string[]         templates to run based on template ids (comma-separated, file, allow-wildcard)   -eid, -exclude-id string[]         templates to exclude based on template ids (comma-separated, file)   -it, -include-templates string[]   path to template file or directory to be executed even if they are excluded either by default or configuration   -et, -exclude-templates string[]   path to template file or directory to exclude (comma-separated, file)   -em, -exclude-matchers string[]    template matchers to exclude in result   -s, -severity value[]              templates to run based on severity. Possible values: info, low, medium, high, critical, unknown   -es, -exclude-severity value[]     templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown   -pt, -type value[]                 templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript   -ept, -exclude-type value[]        templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript   -tc, -template-condition string[]  templates to run based on expression conditionOUTPUT:   -o, -output string            output file to write found issues/vulnerabilities   -sresp, -store-resp           store all request/response passed through nuclei to output directory   -srd, -store-resp-dir string  store all request/response passed through nuclei to custom directory (default "output")   -silent                       display findings only   -nc, -no-color                disable output content coloring (ANSI escape codes)   -j, -jsonl                    write output in JSONL(ines) format   -irr, -include-rr -omit-raw   include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use -omit-raw] (default true)   -or, -omit-raw                omit request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only)   -ot, -omit-template           omit encoded template in the JSON, JSONL output   -nm, -no-meta                 disable printing result metadata in cli output   -ts, -timestamp               enables printing timestamp in cli output   -rdb, -report-db string       nuclei reporting database (always use this to persist report data)   -ms, -matcher-status          display match failure status   -me, -markdown-export string  directory to export results in markdown format   -se, -sarif-export string     file to export results in SARIF format   -je, -json-export string      file to export results in JSON format   -jle, -jsonl-export string    file to export results in JSONL(ine) format   -rd, -redact string[]         redact given list of keys from query parameter, request header and bodyCONFIGURATIONS:   -config string                        path to the nuclei configuration file   -tp, -profile string                  template profile config file to run   -tpl, -profile-list                   list community template profiles   -fr, -follow-redirects                enable following redirects for http templates   -fhr, -follow-host-redirects          follow redirects on the same host   -mr, -max-redirects int               max number of redirects to follow for http templates (default 10)   -dr, -disable-redirects               disable redirects for http templates   -rc, -report-config string            nuclei reporting module configuration file   -H, -header string[]                  custom header/cookie to include in all http request in header:value format (cli, file)   -V, -var value                        custom vars in key=value format   -r, -resolvers string                 file containing resolver list for nuclei   -sr, -system-resolvers                use system DNS resolving as error fallback   -dc, -disable-clustering              disable clustering of requests   -passive                              enable passive HTTP response processing mode   -fh2, -force-http2                    force http2 connection on requests   -ev, -env-vars                        enable environment variables to be used in template   -cc, -client-cert string              client certificate file (PEM-encoded) used for authenticating against scanned hosts   -ck, -client-key string               client key file (PEM-encoded) used for authenticating against scanned hosts   -ca, -client-ca string                client certificate authority file (PEM-encoded) used for authenticating against scanned hosts   -sml, -show-match-line                show match lines for file templates, works with extractors only   -ztls                                 use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default   -sni string                           tls sni hostname to use (default: input domain name)   -dka, -dialer-keep-alive value        keep-alive duration for network requests.   -lfa, -allow-local-file-access        allows file (payload) access anywhere on the system   -lna, -restrict-local-network-access  blocks connections to the local / private network   -i, -interface string                 network interface to use for network scan   -at, -attack-type string              type of payload combinations to perform (batteringram,pitchfork,clusterbomb)   -sip, -source-ip string               source ip address to use for network scan   -rsr, -response-size-read int         max response size to read in bytes   -rss, -response-size-save int         max response size to read in bytes (default 1048576)   -reset                                reset removes all nuclei configuration and data files (including nuclei-templates)   -tlsi, -tls-impersonate               enable experimental client hello (ja3) tls randomization   -hae, -http-api-endpoint string       experimental http api endpointINTERACTSH:   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templatesFUZZING:   -ft, -fuzzing-type string     overrides fuzzing type set in template (replace, prefix, postfix, infix)   -fm, -fuzzing-mode string     overrides fuzzing mode set in template (multiple, single)   -fuzz                         enable loading fuzzing templates (Deprecated: use -dast instead)   -dast                         enable / run dast (fuzz) nuclei templates   -dfp, -display-fuzz-points    display fuzz points in the output for debugging   -fuzz-param-frequency int     frequency of uninteresting parameters for fuzzing before skipping (default 10)   -fa, -fuzz-aggression string  fuzzing aggression level controls payload count for fuzz (low, medium, high) (default "low")UNCOVER:   -uc, -uncover                  enable uncover engine   -uq, -uncover-query string[]   uncover search query   -ue, -uncover-engine string[]  uncover search engine (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google) (default shodan)   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")   -ul, -uncover-limit int        uncover results to return (default 100)   -ur, -uncover-ratelimit int    override ratelimit of engines with unknown ratelimit (default 60 req/min) (default 60)RATE-LIMIT:   -rl, -rate-limit int               maximum number of requests to send per second (default 150)   -rld, -rate-limit-duration value   maximum number of requests to send per second (default 1s)   -rlm, -rate-limit-minute int       maximum number of requests to send per minute (DEPRECATED)   -bs, -bulk-size int                maximum number of hosts to be analyzed in parallel per template (default 25)   -c, -concurrency int               maximum number of templates to be executed in parallel (default 25)   -hbs, -headless-bulk-size int      maximum number of headless hosts to be analyzed in parallel per template (default 10)   -headc, -headless-concurrency int  maximum number of headless templates to be executed in parallel (default 10)   -jsc, -js-concurrency int          maximum number of javascript runtimes to be executed in parallel (default 120)   -pc, -payload-concurrency int      max payload concurrency for each template (default 25)   -prc, -probe-concurrency int       http probe concurrency with httpx (default 50)OPTIMIZATIONS:   -timeout int                     time to wait in seconds before timeout (default 10)   -retries int                     number of times to retry a failed request (default 1)   -ldp, -leave-default-ports       leave default HTTP/HTTPS ports (eg. host:80,host:443)   -mhe, -max-host-error int        max errors for a host before skipping from scan (default 30)   -te, -track-error string[]       adds given error to max-host-error watchlist (standard, file)   -nmhe, -no-mhe                   disable skipping host from scan based on errors   -project                         use a project folder to avoid sending same request multiple times   -project-path string             set a specific project path (default "/tmp")   -spm, -stop-at-first-match       stop processing HTTP requests after the first match (may break template/workflow logic)   -stream                          stream mode - start elaborating without sorting the input   -ss, -scan-strategy value        strategy to use while scanning(auto/host-spray/template-spray) (default auto)   -irt, -input-read-timeout value  timeout on input read (default 3m0s)   -nh, -no-httpx                   disable httpx probing for non-url input   -no-stdin                        disable stdin processingHEADLESS:   -headless                        enable templates that require headless browser support (root user on Linux will disable sandbox)   -page-timeout int                seconds to wait for each page in headless mode (default 20)   -sb, -show-browser               show the browser on the screen when running templates with headless mode   -ho, -headless-options string[]  start headless chrome with additional options   -sc, -system-chrome              use local installed Chrome browser instead of nuclei installed   -lha, -list-headless-action      list available headless actionsDEBUG:   -debug                    show all requests and responses   -dreq, -debug-req         show all sent requests   -dresp, -debug-resp       show all received responses   -p, -proxy string[]       list of http/socks5 proxy to use (comma separated or file input)   -pi, -proxy-internal      proxy all internal requests   -ldf, -list-dsl-function  list all supported DSL function signatures   -tlog, -trace-log string  file to write sent requests trace log   -elog, -error-log string  file to write sent requests error log   -version                  show nuclei version   -hm, -hang-monitor        enable nuclei hang monitoring   -v, -verbose              show verbose output   -profile-mem string       optional nuclei memory profile dump file   -vv                       display templates loaded for scan   -svd, -show-var-dump      show variables dump for debugging   -ep, -enable-pprof        enable pprof debugging server   -tv, -templates-version   shows the version of the installed nuclei-templates   -hc, -health-check        run diagnostic check upUPDATE:   -up, -update                      update nuclei engine to the latest released version   -ut, -update-templates            update nuclei-templates to latest released version   -ud, -update-template-dir string  custom directory to install / update nuclei-templates   -duc, -disable-update-check       disable automatic nuclei/templates update checkSTATISTICS:   -stats                    display statistics about the running scan   -sj, -stats-json          display statistics in JSONL(ines) format   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)CLOUD:   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)   -tid, -team-id string           upload scan results to given team id (optional) (default "none")   -cup, -cloud-upload             upload scan results to pdcp dashboard [DEPRECATED use -dashboard]   -sid, -scan-id string           upload scan results to existing scan id (optional)   -sname, -scan-name string       scan name to set (optional)   -pd, -dashboard                 upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard   -pdu, -dashboard-upload string  upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboardAUTHENTICATION:   -sf, -secret-file string[]  path to config file containing secrets for nuclei authenticated scan   -ps, -prefetch-secrets      prefetch secrets from the secrets fileEXAMPLES:Run nuclei on single host:  $ nuclei -target example.comRun nuclei with specific template directories:  $ nuclei -target example.com -t http/cves/ -t sslRun nuclei against a list of hosts:  $ nuclei -list hosts.txtRun nuclei with a JSON output:  $ nuclei -target example.com -json-export output.jsonRun nuclei with sorted Markdown outputs (with environment variables):  $ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/Additional documentation is available at: https://docs.nuclei.sh/getting-started/running
```  
### 单目标扫描  
  
要对 Web 应用程序执行快速扫描：  
```
nuclei -target https://example.com
```  
### 扫描多个目标  
  
Nuclei 可以通过提供目标列表来处理批量扫描。您可以使用包含多个 URL 的文件。  
```
nuclei -targets urls.txt
```  
### 网络扫描  
  
这将扫描整个子网以查找与网络相关的问题，例如开放端口或配置错误的服务。  
```
nuclei -target 192.168.1.0/24
```  
### 使用自定义模板进行扫描  
  
使用自定义模板进行扫描  
```
nuclei -u https://example.com -t /path/to/your-template.yaml
```  
### 将 Nuclei 连接至 ProjectDiscovery  
  
您可以在您的机器上运行扫描并将结果上传到云平台进行进一步分析和补救。  
```
nuclei -target https://example.com -dashboard
```  
```
原文链接:https://github.com/projectdiscovery/nuclei
```  
  
  
  
