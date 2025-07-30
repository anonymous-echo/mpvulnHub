#  【安全圈】施乐打印机漏洞使攻击者能够从 LDAP 和 SMB 中获取身份验证数据   
 安全圈   2025-03-13 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgJJuqW5y6mSvR0HmSw8A5EWLdtu23WN1h5fy3zlfnWpC5uiaoUQlLjSbLQU3kCtsKzTOdCvNzONicQ/640?wx_fmt=png&from=appmsg "")  
  
企业级 Xerox Versalink C7025 多功能打印机 (MFP) 中的多个漏洞使攻击者能够拦截来自轻量级目录访问协议 (LDAP) 和服务器消息块 (SMB) 服务的身份验证凭据。   
  
这些漏洞被指定为 CVE-2024-12510 和 CVE-2024-12511，允许恶意行为者执行“回传攻击”——一种将设备身份验证尝试重定向到攻击者控制的系统的技术。   
  
这些漏洞由 Rapid7 首席物联网研究员 Deral Heiland 发现，影响施乐广泛部署的企业打印机的固件版本 57.69.91 及更早版本。  
## LDAP 回传漏洞 (CVE-2024-12510)  
  
LDAP 漏洞使具有打印机 Web 界面管理权限的攻击者能够将 LDAP 服务器 IP 地址重新配置为恶意主机。   
  
一旦修改，通过打印机的“用户映射”功能发起的任何 LDAP 身份验证尝试都会将明文凭据传输到攻击者的服务器。   
  
这种攻击针对的是使用 LDAP 进行集中用户身份验证的组织，需要：  
- 打印机上的有效 LDAP 配置可确保正常运行  
  
- 泄露打印机的管理员凭据（默认密码或弱密码）  
  
- 通过网络访问来修改 LDAP 服务器设置  
  
安全分析师使用基于 Python 的 LDAP 监听器演示了此次攻击，并在打印机发起的身份验证请求期间实时捕获凭据。   
  
获取的凭证可以允许攻击者访问包含敏感用户属性和权限的企业目录。  
## SMB/FTP 凭证拦截（CVE-2024-12511）  
  
次要漏洞针对的是打印机的扫描到网络功能。攻击者修改设备地址簿中的 SMB/FTP 服务器条目，可以将文件扫描重定向到恶意主机。此技术可捕获：  
- 使用 SMB 时 NetNTLMv2 哈希，从而启用针对 Active Directory 的中继攻击  
  
- 如果配置了 FTP 身份验证，则提供明文凭据  
  
Metasploit 的辅助/服务器/捕获/smb 模块可以收集 NetNTLMv2 挑战，然后攻击者可以离线破解它或将其中继到加入域的系统。   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgJJuqW5y6mSvR0HmSw8A5Ezu5nXy1kHmtYKwuuC6xibWgSMUdw6BRWIsZ88BiaxmDBiaeYzVJ5dOYKw/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员的测试表明，当打印机使用特权服务帐户进行扫描到文件夹工作流程时，域管理员帐户被成功入侵。  
## 企业影响和攻击场景  
  
这些漏洞存在严重风险，因为：  
- 横向移动潜力：泄露的域凭证使攻击者能够从打印机转向文件服务器、ERP 系统和云资源。  
  
持久性机会：捕获的 SMB 哈希有助于黄金票证攻击和持久的 AD 立足点。  
  
物理访问利用：攻击者可以通过打印机的控制面板在本地执行攻击，而无需网络访问。  
  
在一个演示的攻击链中，研究人员通过默认凭据获得管理员访问权限（施乐设备通常保留出厂默认设置），将 LDAP 设置修改为攻击者 IP，通过“测试连接”功能触发 LDAP 同步，并使用捕获的凭据访问包含 PII 的 HR 数据库。  
  
缓解策略   
  
施乐发布了修补固件（版本 57.69.92+），解决了这两个 CVE。如果无法立即修补：  
- 轮换所有打印机服务帐户密码  
  
- 通过管理控制台禁用未使用的协议（FTP/SMBv1）  
  
- 实施网络分段，将打印机通信限制在必要端口上  
  
- 为打印机管理访问启用 MFA  
  
随着修补固件的推出，组织必须迅速采取行动，在威胁行为者大规模利用这些漏洞之前关闭此攻击媒介。  
  
  
来源：https://cybersecuritynews.com/xerox-printers-vulnerability-ldap-smb/  
  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】美国政府称 2024 年美国人因欺诈损失创纪录 125 亿美元](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=1&sn=7aa71495a16a8590c5a5dbaf2a299a09&scene=21#wechat_redirect)  
  
  
  
[【安全圈】朝鲜 Lazarus 黑客通过 npm 软件包感染数百人](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=2&sn=bbe1548572f3323cc8067fa2bc9bdf6b&scene=21#wechat_redirect)  
  
  
  
[【安全圈】瑞士关键行业面临新的 24 小时网络攻击报告规则](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=3&sn=cbceff6b7d8cacc138082e8b186207c7&scene=21#wechat_redirect)  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068401&idx=1&sn=5600b75d725f6e90a4cbfddf6a7e10cc&scene=21#wechat_redirect)  
[【安全圈】SideWinder APT 利用增强的工具集瞄准海事和核能领域](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068449&idx=4&sn=90a8bf33c53d8d8882985f1e9798ea93&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
