#  SonicWall防火墙认证绕过漏洞正遭大规模利用   
邑安科技  邑安全   2025-02-18 04:22  
  
更多全球网络安全资讯尽在邑安全  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8siciaZfAAiaQdMG0rpiaM7sBhQMvaecQxSespVyPvbNTYGIzx9kDuiagPRTkyVafeZtZHmFGlJyBIBUnw/640?wx_fmt=jpeg&from=appmsg "")  
  
网络安全公司警告称，SonicWall防火墙中存在的一个严重认证绕过漏洞正在被积极利用，该漏洞编号为CVE-2024-53704 。2025年2月10日，随着Bishop Fox的研究人员公开发布了概念验证（PoC）漏洞利用代码，未修补设备组织面临的风险大大增加。  
## 漏洞详情与攻击方式  
  
CVE-2024-53704是一个存在于SonicOS SSL VPN认证机制中的高危漏洞，影响SonicWall Gen 6、Gen 7和TZ80系列防火墙。攻击者可以通过向/cgi-bin/sslvpnclient端点发送包含base64编码的空字节字符串的特制会话cookie，从而远程劫持活动的VPN会话。  
  
成功利用该漏洞可以绕过多因素认证（MFA），暴露私有网络路由，并允许未经授权的用户访问内部资源。此外，被劫持的会话还可用于终止合法用户连接。  
## 漏洞被快速武器化  
  
SonicWall最初于2025年1月7日披露了该漏洞，并敦促用户立即修补。当时厂商并未报告漏洞被实际利用的证据。然而，随着Bishop Fox在2月10日发布PoC代码，攻击门槛大幅降低。2月12日，Arctic Wolf观察到源自不到十个不同IP地址的攻击尝试，这些IP主要托管在虚拟私有服务器（VPS）上。  
  
安全分析师认为，漏洞被快速武器化是因为其严重性和SonicWall设备曾被Akira和Fog等勒索软件组织针对性攻击的历史。截至2月7日，Bishop Fox统计发现仍有超过4,500台暴露于互联网的SonicWall SSL VPN（Virtual Private Network）服务器未修补。受影响的固件版本包括：  
- SonicOS 7.1.x（最高到7.1.1-7058）  
  
- SonicOS 7.1.2-7019  
  
- SonicOS 8.0.0-8035  
  
修复版本（如SonicOS 8.0.0-8037和7.1.3-7015）已于2025年1月发布。  
  
漏洞利用模式与此前的攻击活动类似。2024年底，Akira勒索软件组织利用被攻破的SonicWall VPN账户渗透网络，通常在初始访问后的几小时内加密数据。  
## 风险与应对建议  
  
Arctic Wolf警告称，CVE-2024-53704可能成为勒索软件部署、凭证窃取或间谍活动的入口。SonicWall和网络安全机构强调，用户需采取以下紧急措施：  
1. 升级固件到修复版本（如8.0.0-8037或7.1.3-7015）。  
  
1. 在无法立即修补的情况下，关闭公共接口的SSL VPN功能。  
  
1. 限制VPN访问到受信任的IP范围，并为剩余用户强制启用MFA。  
  
随着漏洞被大规模利用，组织必须优先修补以降低风险。PoC代码公开、攻击可行性高以及SonicWall在企业网络中的广泛应用，都凸显了问题的紧迫性。  
  
正如Arctic Wolf所警告的那样，鉴于漏洞严重性和勒索软件攻击者的敏捷性，拖延修补可能导致“灾难性的网络入侵”。  
  
原文来自: freebuf.com  
  
原文链接: https://cybersecuritynews.com/firewall-authentication-bypass-vulnerability/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
