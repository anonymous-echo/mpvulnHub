#  【漏洞通告】Oracle Agile PLM Framework文件泄露漏洞安全风险通告   
 嘉诚安全   2024-11-21 03:00  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Oracle发布安全公告，攻击者正在积极利用Oracle Agile PLM Framework文件泄露漏洞获取敏感信息，漏洞编号为：  
CVE-2024-21287。  
  
  
Oracle Agile PLM(Product Lifecycle Management) Framework是Oracle提供的一种产品生命周期管理解决方案，旨在帮助企业有效地管理产品的整个生命周期，包括从概念设计到生产、分销、售后等所有环节的流程和数据。它帮助企业通过集成产品数据、流程和协作，来提高产品开发的效率、降低成本、确保合规性并加速创新。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快安装安全补丁，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
，  
已发现被  
**在野利用**  
。Oracle Agile PLM Framework（组件：Software Development Kit和Pzrocess Extension）中存在信息泄露漏洞，未经身份验证的攻击者可以通过HTTP访问并利用该漏洞，从而以PLM应用程序使用的权限下载目标系统上可访问的文件，成功利用该漏洞可能导致未授权访问并获取Oracle Agile PLM Framework中存储的敏感数据或文件。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Oracle Agile PLM Framework版本9.3.6  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前Oracle已发布了该漏洞的补丁，受影响用户可及时更新。  
  
下载链接：  
  
https://www.oracle.com/security-alerts/alert-cve-2024-21287.html  
  
参考链接：  
  
https://blogs.oracle.com/security/post/alert-cve-2024-21287  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-21287  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
