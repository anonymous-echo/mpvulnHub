#  【漏洞通告】Ivanti Endpoint Manager SQL注入漏洞安全风险通告   
 嘉诚安全   2024-11-14 10:49  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Ivanti官方修复了一个Ivanti Endpoint Manager SQL注入漏洞，漏洞编号为：CVE-2024-50330。  
  
  
Ivanti Endpoint Manager（EPM）是由Ivanti公司开发的一款综合性端点管理解决方案，帮助企业有效管理和保护网络中的端点设备，包括桌面、笔记本电脑、服务器、移动设备和虚拟环境等。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快下载相关补丁，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
在Ivanti EPM的代理门户中，存在一个SQL注入漏洞，经研判，该漏洞为  
**高危**  
漏洞  
。该漏洞允许远程未经身份验证的攻击者执行远程代码，从而控制受影响的系统，造成敏感信息泄露甚至获取系统权限等危害。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
Ivanti Endpoint Manager 2024 <= 2024 September Security Update  
  
Ivanti Endpoint Manager 2022 <= 2022 SU6 September Security Update  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
Ivanti Endpoint Manager 2024 November Security Update  
  
Ivanti Endpoint Manager 2022 SU6 November Security Update  
  
官方补丁下载地址：https://download.ivanti.com/downloads/Patch/component/EPM2024/Security/Flat/EPM_2024_Flat_November_2024_Patch.zip  
  
https://download.ivanti.com/downloads/Patch/component/EPM2022/Security/SU6/EPM_2022_SU6_November_2024_Patch.zip  
  
参考链接：  
  
https://forums.ivanti.com/s/article/Security-Advisory-EPM-November-2024-for-EPM-2024-and-EPM-2022  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-50330  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
