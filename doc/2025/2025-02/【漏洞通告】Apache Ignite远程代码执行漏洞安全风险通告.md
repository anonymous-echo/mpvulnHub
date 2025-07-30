#  【漏洞通告】Apache Ignite远程代码执行漏洞安全风险通告   
 嘉诚安全   2025-02-19 08:43  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache Ignite远程代码执行漏洞，漏洞编号为：  
CVE-2024-52577。  
  
  
Apache Ignite是一个高性能、分布式数据库和计算平台，专为大规模数据处理和实时分析设计。它支持内存计算、SQL查询、键值存储、数据流处理等功能，广泛应用于大数据、物联网、金融服务等领域。Ignite提供高可用性、扩展性和低延迟，支持与其他大数据框架（如Hadoop、Spark）集成。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞  
。  
攻击者可通过发送恶意消息至易受攻击的Ignite服务器，从而绕过类序列化过滤机制并执行任意代码。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
2.6.0 <= Apache Ignite < 2.17.0  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
Apache Ignite团队已在版本2.17.0中修复了此漏洞。建议受影响版本的用户尽快升级到2.17.0或更高版本，以解决该问题。  
  
下载链接：  
  
https://github.com/apache/ignite/releases/tag/2.17.0/  
  
2.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。  
  
加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
3.参考链接  
  
http://www.openwall.com/lists/oss-security/2025/02/14/2  
  
https://lists.apache.org/thread/1bst0n27m9kb3b6f6hvlghn182vqb2hh  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
  
