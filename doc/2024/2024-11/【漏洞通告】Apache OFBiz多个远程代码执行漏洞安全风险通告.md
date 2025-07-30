#  【漏洞通告】Apache OFBiz多个远程代码执行漏洞安全风险通告   
 嘉诚安全   2024-11-19 01:28  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache OFBiz中修复了两个远程代码执行漏洞，漏洞编号分别是：CVE-2024-47208和CVE-2024-48962。  
  
  
Apache OFBiz是一个著名的电子商务平台，提供了创建基于最新J2EE/ XML规范和技术标准，构建大中型企业级、跨平台、跨数据库、跨应用服务器的多层、分布式电子商务类WEB应用系统的框架。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
**1、CVE-2024-47208**  
  
Apache OFBiz远程代码执行漏洞，经研判，该漏洞为  
**高危**漏洞。由于对URL校验不严格，攻击者可通过构造恶意URL绕过校验逻辑并注入Groovy表达式代码或触发服务器端请求伪造（SSRF）攻击，导致远程代码执行或访问未授权资源。  
  
  
**2、CVE-2024-48962**  
  
Apache OFBiz远程代码执行漏洞，经研判，该漏洞为  
**高危**漏洞  
。由于在处理URL参数时未正确对特殊字符进行转义和编码，攻击者可以构造恶意URL参数绕过SameSite cookie限制，通过目标重定向和服务器端模板注入（SSTI）实现跨站请求伪造（CSRF）攻击，进而触发远程代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Apache OFBiz < 18.12.17  
  
  
**修复建议**  
  
  
  
  
  
  
  
  
目前这些漏洞已经修复，受影响用户可升级到以下版本：  
  
Apache OFBiz >= 18.12.17  
  
下载链接：  
  
https://ofbiz.apache.org/download.html  
  
参考链接：https://lists.apache.org/thread/ls1w4ywdobn4hok1tpfm1x23n0q59o74  
  
https://issues.apache.org/jira/browse/OFBIZ-13158  
  
https://issues.apache.org/jira/browse/OFBIZ-13162  
  
https://www.openwall.com/lists/oss-security/2024/11/16/3  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
