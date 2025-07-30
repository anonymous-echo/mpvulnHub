#  不靠谱的补丁！补丁再次被绕过-声音文件触发的Microsoft Outlook零点击漏洞链   
 网络安全应急技术国家工程中心   2023-12-20 15:15  
  
Akamai的安全研究人员正在分享Microsoft今年早些时候针对Outlook零点击远程代码执行漏洞发布的补丁的多个绕过细节。最初的问题被追踪为CVE-2023-23397，在俄罗斯国家支持的黑客组织在野外利用该问题大约一年后，微软于2023年3月修复了该漏洞。未经身份验证的攻击者可以通过发送包含指定为路径的声音通知的电子邮件提醒来发起攻击，强制Outlook客户端连接到攻击者的服务器，从而导致Net-NTLMv2哈希发送到服务器。2023年12月，微软与波兰网络司令部(DKWOC)一起发布消息称，他们发现同一威胁参与者最近试图利用该漏洞。  
  
利用该漏洞不需要用户交互，因为当服务器收到并处理电子邮件时，该漏洞会立即触发。微软通过调用API函数解决了这个问题，该函数将检查路径以确保它没有引用互联网URL。然而，通过在电子邮件中包含精心设计的URL，被调用的函数可能会被欺骗，将远程路径视为本地路径。该绕过漏洞由Akamai发现并跟踪为CVE-2023-29324，2023年5月被Microsoft修复。**然而，CVE-2023-29324缺陷只是Akamai在研究Outlook零点击漏洞时发现的绕过方法之一。Akamai最新的报告中披露了又一个补丁绕过漏洞（CVE-2023-35384）和一个音频压缩管理器的漏洞（CVE-2023-36710）。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icV0Ozt1RiccYZy1IFbJzXHsVAThWuyyygga7vqthsbicpTfib5iaeiaOmcD5QTpe5dn4rNxa6PeABrzicoA/640?wx_fmt=jpeg&from=appmsg "")  
  
**补丁再被绕过**  
  
Akamai在本周的一篇由两部分组成的博客文章中表示：“互联网上的攻击者可以将这些漏洞链接在一起，针对Outlook客户端创建完整的、零点击远程代码执行(RCE)攻击。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icV0Ozt1RiccYZy1IFbJzXHsVUbXPWTBKToBoLP4k9uWXjoiayWHUyWZvzQcETaTjInVQnGX1XVux6mg/640?wx_fmt=png&from=appmsg "")  
  
Akamai研究人员发现的第二个补丁绕过漏洞编号为CVE-2023-35384，该漏洞是Microsoft在3月份首次修补的Outlook中的一个关键权限升级漏洞（**第一个补丁绕过漏洞是CVE-2023-29324，已于2023年5月份修复**）。Akamai本周披露的另一个漏洞( CVE-2023-36710，8月份微软已修复)是Windows Media Foundation一项功能中的远程代码执行(RCE)漏洞，与Windows解析声音文件的方式有关。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icV0Ozt1RiccYZy1IFbJzXHsVIs39GlFanINMQ5vMxmPWRrHmj6Gj2nvC65TMEowpaIC2ibb8Oaa0xHQ/640?wx_fmt=png&from=appmsg "")  
  
**关于CVE-2023-36710漏洞的严重性，Akamai表示，攻击者可以在Outlook客户端或其他即时消息应用程序的上下文中成功利用此漏洞，无需用户交互即可实现远程代码执行。**  
  
最早原始漏洞  
CVE-2023-23397的利用流程大致如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icV0Ozt1RiccYZy1IFbJzXHsVHNteTYlKryicQOAub1h5Z1fdfe4Op039ib6tMXfCRNWRgbTpTKBAC8pA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**零点击漏洞利用链**  
  
在Akamai研究人员联系该公司后，微软于8月发布了CVE-2023-35384补丁。该缺陷源于Outlook中的安全功能无法正确验证请求的URL是否位于本地计算机区域、Intranet区域或其他受信任区域。  
  
据Akamai称，攻击者可以通过向受影响的Outlook客户端发送带有自定义通知声音的电子邮件提醒来触发该漏洞。供应商补充说，“攻击者可以指定一个UNC路径，导致客户端从互联网上的任何SMB服务器检索声音文件”，而不是从安全或受信任的区域。  
  
为了触发CVE-2023-35384漏洞，攻击者将利用第一个漏洞发送特制电子邮件，从攻击者控制的服务器下载恶意声音文件。  
  
“当下载的声音文件自动播放时……它可能会导致受害机器上执行代码，”Akamai说。  
  
Akamai安全研究员Ben Barnea表示，攻击者可以单独或以连锁方式利用这两个漏洞。“虽然它们中的每一个都是一个有点‘弱’的漏洞，但通过将它们链接在一起对抗Outlook，我们实现了强大的零点击RCE漏洞，”他说。  
  
**补丁上再打补丁**  
  
如前所述，这是Akamai研究人员第二次找到解决Microsoft在3月份针对Outlook权限升级缺陷（跟踪为CVE-2023-23397）的补丁的方法。该原始漏洞为攻击者提供了一种使用声音文件窃取用户口令哈希并对用户有权访问的服务进行身份验证的方法。就在12月4日，微软警告称，俄罗斯的Fancy Bear组织（又名Forest Blizzard）正在积极利用该漏洞对Exchange服务器中的电子邮件帐户进行未经授权的访问。  
  
微软最初的补丁试图确保Outlook在处理包含自定义通知提醒的电子邮件之前，首先验证声音文件URL的安全性。该补丁旨在确保如果自定义通知声音的URL是从不受信任/未经验证的域引入的，则会使用Outlook的默认通知声音。  
  
但随后，Akamai研究人员在探索该补丁后发现，他们可以通过向Microsoft更新中的功能添加单个字符来绕过该补丁。这一发现促使微软为该问题分配了一个单独的CVE (CVE-2023-29324)，并于5月份为其发布了补丁。  
  
**Akamai本周详细介绍的新绕过也是源于原始补丁中的一个问题，而且它可能不是补丁中发现的最后一个问题。**  
  
“原始漏洞（CVE-2023-23397）的补丁使用了一个名为‘MapUrlToZone’的函数来缓解自定义提醒声音功能的滥用，”Barnea解释道，并指出该函数非常复杂，并且增加了攻击者可用的攻击面。  
  
“结果，补丁添加了更多也存在漏洞的代码，”他说。“我们建议删除被滥用的功能，而不是使用补丁，因为该功能弊大于利。”  
  
**Akamai的研究表明，Outlook中的攻击面仍然存在，并且可以发现和利用新的漏洞。尽管Microsoft修补了Exchange 以删除包含PidLidReminderFileParameter属性的邮件，但不能排除绕过此缓解措施的可能性。**  
  
  
**参考资源**  
  
1、https://www.akamai.com/blog/security-research/chaining-vulnerabilities-to-achieve-rce-part-one  
  
2、https://www.darkreading.com/vulnerabilities-threats/researchers-release-details-on-two-patched-outlook-zero-click-flaws  
  
3、https://www.securityweek.com/outlook-plays-attacker-tunes-vulnerability-chain-leading-to-zero-click-rce/  
  
4、https://www.darkreading.com/remote-workforce/microsoft-fixes-failed-patch-that-exploited-outlook-vulnerability  
  
