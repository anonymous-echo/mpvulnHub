> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583835&idx=1&sn=2754957b43cf398a180399f4a359413c

#  Citrix Bleed 2漏洞被网络犯罪分子利用进行攻击  
胡金鱼  嘶吼专业版   2025-07-16 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
据网络安全公司ReliaQuest称，NetScaler ADC和网关的一个关键漏洞“Citrix Bleed 2”（CVE-2025-5777）现在很可能被利用在攻击中，Citrix设备上的可疑会话有所增加。  
  
Citrix Bleed 2，由网络安全研究员Kevin Beaumont命名，因为它与最初的Citrix Bleed （CVE-2023-4966）相似，是一个内存读取漏洞，允许未经身份验证的攻击者访问通常不可访问的内存部分。  
  
这可能允许攻击者从面向公众的网关和虚拟服务器窃取会话令牌、凭据和其他敏感数据，使他们能够劫持用户会话并绕过多因素身份验证（MFA）。  
  
Citrix的顾问也确认了这一风险，提醒用户安装安全更新以阻止访问任何被劫持的会话后，结束所有ICA和PCoIP会话。  
  
该漏洞被追踪为CVE-2025-5777，Citrix于2025年6月17日解决了该漏洞，没有任何活跃利用的报告。然而，Beaumont警告说上周存在被利用的可能性较高。  
  
研究人员的担忧似乎是有根据的，因为ReliaQuest表示，CVE-2025-5777已经被用于有针对性的攻击。  
  
虽然没有公开利用CVE-2025-5777（被称为“Citrix Bleed 2”）的报道，但ReliaQuest认为，攻击者正在积极利用这一漏洞，获得对目标环境的初始访问权限。  
  
这一结论是基于对最近实际攻击的以下观察得出的：  
  
**·**  
被劫持的Citrix web会话在没有用户交互的情况下被授予身份验证，这表明攻击者使用被盗的会话令牌绕过了MFA。  
  
**·**  
攻击者在合法和可疑的IP地址上重复使用相同的Citrix会话，这表明会话劫持和从未经授权的来源重播。  
  
**·**  
LDAP查询是在访问后发起的，这表明攻击者执行了Active Directory侦察来映射用户、组和权限。  
  
**·**  
adeexplorer64 .exe的多个实例跨系统运行，表明协调的域侦察和对各种域控制器的连接尝试。  
  
**·**  
Citrix会话起源于与消费者VPN提供商（如DataCamp）相关的数据中心ip，这表明攻击者通过匿名基础设施进行混淆。  
  
上述情况与未经授权访问Citrix后的开发活动一致，强化了CVE-2025-5777正在被利用的评估。  
  
为了防止这种活动，可能受到影响的用户应该升级到14.1-43.56+、13.1-58.32+或13.1-FIPS/NDcPP 13.1-37.235+版本来修复漏洞。  
  
在安装最新固件后，管理员应该终止所有活动的ICA和PCoIP会话，因为它们可能已经被劫持了。  
  
在终止活动会话之前，管理员应该首先使用show icconnection命令和NetScaler Gateway > PCoIP > Connections检查它们是否存在可疑活动。在检查活动会话后，管理员可以使用以下命令终止它们：终止所有连接、终止pcoipconnection -all。如果无法立即安装安全更新，建议通过网络acl或防火墙规则限制外部对NetScaler的访问。  
  
在被问到关于CVE-2025-5777是否被积极利用的问题时，Citrix表示没有发现任何利用的迹象。然而，另一个Citrix漏洞，跟踪为CVE-2025-6543，正在攻击中被利用，导致NetScaler设备上的拒绝服务条件。  
Citrix  
表示，这个漏洞和CVE-2025-5777漏洞在同一个模块中，但是不同的漏洞。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/citrix-bleed-2-flaw-now-believed-to-be-exploited-in-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wpkib3J60o287jwk8LWD9icmgWlahS21WBibH0Iz3x2kLShrmHpicmyoLLZjhkG6s61yDMgXpJ74WhrDYlWupFxzKg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icEjy5ZrpCcgr4BicXicPv08DSsrgibDcJQpvwkZoO4OqdIpJNhj6TO5xV0ic0AnVf7f2kcPnNevQlTtQ/640?wx_fmt=png "")  
  
  
