#  【漏洞通告】Adobe ColdFusion任意文件读取漏洞安全风险通告   
 嘉诚安全   2024-03-27 15:57  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Adobe ColdFusion发布新版本，修复了一个任意文件读取漏洞，  
漏洞编号为：CVE-2024-20767。  
  
  
Adobe ColdFusion是美国奥多比（Adobe）公司的一套快速应用程序开发平台，包括集成开发环境和脚本语言。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**漏洞，漏洞的  
**细节及**  
**PoC/EXP****已公开。**由于Adobe ColdFusion的访问控制不当，未经身份认证的远程攻击者可以构造恶意请求读取目标服务器上的任意文件，泄露敏感信息。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
ColdFusion 2023 <= Update 6  
  
ColdFusion 2021 <= Update 12  
  
  
**修复建议**  
  
  
  
  
  
  
  
  
根据影响版本中的信息，建议相关用户尽快更新至安全版本：  
  
ColdFusion 2023 >= Update 7  
  
ColdFusion 2021 >= Update 13  
  
  
参考链接：  
  
https://helpx.adobe.com/coldfusion/kb/coldfusion-2023-update-7.html?wcmmode=disabled  
  
https://helpx.adobe.com/coldfusion/kb/coldfusion-2021-update-13.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
