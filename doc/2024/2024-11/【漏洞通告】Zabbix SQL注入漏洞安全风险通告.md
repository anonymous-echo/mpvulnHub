#  【漏洞通告】Zabbix SQL注入漏洞安全风险通告   
 嘉诚安全   2024-11-29 07:50  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Zabbix中修复了一个SQL注入漏洞，漏洞编号为：  
CVE-2024-42327。  
  
  
Zabbix是一个基于WEB界面的提供分布式系统监视以及网络监视功能的企业级开源监控解决方案，可以用来监控服务器、硬件、网络等。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。Zabbix前端的CUser类中的addRelatedObjects函数未对输入数据进行充分验证和转义，导致具有API访问权限的恶意用户可以通过user.get API传递特制输入触发SQL注入攻击，进而利用该漏洞实现权限提升或访问敏感数据。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Zabbix 6.0.0 - 6.0.31  
  
Zabbix 6.4.0 - 6.4.16  
  
Zabbix 7.0.0  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到Zabbix 6.0.32rc1、Zabbix 6.4.17rc1、Zabbix 7.0.1rc1或更高版本。  
  
下载链接：  
  
https://github.com/zabbix/zabbix/tags  
  
https://www.zabbix.com/download  
  
参考链接：  
  
https://support.zabbix.com/browse/ZBX-25623  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-42327  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
