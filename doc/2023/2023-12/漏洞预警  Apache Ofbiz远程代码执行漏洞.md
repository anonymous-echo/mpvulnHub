#  漏洞预警 | Apache Ofbiz远程代码执行漏洞   
浅安  浅安安全   2023-12-30 08:00  
  
**0x00 漏洞编号**  
- # CVE-2023-51467  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache OFBiz是Apache的一套企业资源计划系统，提供了一整套基于Java的Web应用程序组件和工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWb8d466BsKYMQRW3jrCjGvEV4QWVVDKTqwx3KR0YI4OpBchpucKVnUt3vic275ibHTInsxFWehWFDA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2023-51467**  
  
**漏洞类型：**  
远程代码执行****  
  
**影响：**  
  
执行任意代码  
  
****  
  
**简述：**  
Apache Ofbiz中存在远程代码执行漏洞，由于Apache Ofbiz存在一个权限校验逻辑错误，导致可以通过构造特殊请求绕过登录验证请求后端接口，结合后台相关功能可以在服务器上执行任意代码。  
###   
  
**0x04 影响版本**  
- Apache OFBiz < 18.12.11  
  
**0x05****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://ofbiz.apache.org/  
  
  
  
