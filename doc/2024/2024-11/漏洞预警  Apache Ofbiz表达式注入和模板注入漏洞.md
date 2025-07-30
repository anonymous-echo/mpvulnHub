#  漏洞预警 | Apache Ofbiz表达式注入和模板注入漏洞   
浅安  浅安安全   2024-11-26 00:01  
  
**0x00 漏洞编号**  
- CVE-2024-47208  
  
- CVE-2024-48962  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache OFBiz是Apache的一套企业资源计划系统，提供了一整套基于Java的Web应用程序组件和工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWb8d466BsKYMQRW3jrCjGvEV4QWVVDKTqwx3KR0YI4OpBchpucKVnUt3vic275ibHTInsxFWehWFDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-47208**  
  
**漏洞类型：**  
表达式注入****  
  
**影响：**  
未授权访问  
  
****  
  
**简述：**  
Apache OFBiz存在表达式注入漏洞，由于对URL校验不严格，攻击者可通过构造恶意URL绕过校验逻辑并注入Groovy表达式代码或触发服务器端请求伪造攻击，导致远程代码执行或访问未授权资源。  
  
CVE-2024-48962  
  
**漏洞类型：模板注入******  
  
**影响：**  
执行任意命令  
  
****  
  
**简述：**  
Apache OFBiz存在模板注入漏洞，由于在处理URL参数时未正确对特殊字符进行转义和编码，攻击者可以构造恶意URL参数绕过SameSite cookie限制，通过目标重定向和服务器端模板注入实现跨站请求伪造攻击，进而触发远程代码执行。  
  
**0x04 影响版本**  
- Apache OFBiz < 18.12.17  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://ofbiz.apache.org/  
  
  
  
