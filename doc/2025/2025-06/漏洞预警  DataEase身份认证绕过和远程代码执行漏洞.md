#  漏洞预警 | DataEase身份认证绕过和远程代码执行漏洞  
浅安  浅安安全   2025-06-08 23:50  
  
**0x00 漏洞编号**  
- CVE-2025-49001  
  
- CVE-2025-49002  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
DataEase是一款开源的数据可视化分析工具。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU6Xlej5bgFtO45c162zLdxNJMgnHXdPma24vOBqoiaISw439NnQ8CKsSw60DTpO31d2KDgfsNFtyw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
CVE-2025-49002  
  
**漏洞类型：**  
身份认证绕过  
****  
  
**影响：执越权访问******  
  
**简述：**  
DataEase数据源中存在  
身份认证绕过  
漏洞，  
由于JWT校验机制错误，导致攻击者可伪造JWT令牌绕过身份验证流程，进而访问系统。  
  
CVE-2025-49001  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
  
执行任意命令  
  
****  
  
**简述：**  
DataEase数据源中存在  
远程代码执行  
漏洞，  
由于H2数据库模块没有严格过滤用户输入的JDBC连接参数，可使用大小写绕过补丁，进而执行任意命令。  
  
**0x04 影响版本**  
- DataEase <= 2.10.8  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://dataease.io/  
  
  
  
