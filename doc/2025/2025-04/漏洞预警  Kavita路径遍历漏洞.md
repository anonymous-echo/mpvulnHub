#  漏洞预警 | Kavita路径遍历漏洞   
浅安  浅安安全   2025-04-12 00:04  
  
**0x00 漏洞编号**  
- # CVE-2025-31131  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
YesWiki是一个基于PHP和MySQL开发的开源、易用的Wiki平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWuUXNbWxDXwAcpib7wlsy5UCskFBCibcSQKdj0xfuEL0bqlVIYVd0pQLMJmOC2zib1YhUTD3dCnUssw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
CVE-2025-31131  
  
漏洞类型：  
目录遍历****  
  
**影响：**  
获取敏感信息  
  
**简述：**  
YesWiki的/?UrkCEO/edit接口存在路径遍历漏洞，未经身份验证的攻击者可以通过filename参数遍历任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- YesWiki < 4.5.2  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://yeswiki.net/  
  
  
  
