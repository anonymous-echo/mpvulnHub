#  【安全圈】新的 UEFI 安全启动绕过漏洞使系统暴露于恶意 Bootkit   
 安全圈   2025-01-17 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljvUKhLrdazZeNW748aFKwpj85LpSBGhPYPQX7iaVhWGnGrn6gyk168FR5OodibqibL9rQJS7QWa08jQ/640?wx_fmt=jpeg&from=appmsg "")  
  
新发现的漏洞 CVE-2024-7344 被认定为UEFI 安全启动机制中的一个严重缺陷，可能会影响大多数基于 UEFI 的系统。  
  
ESET 的研究人员发现了这一漏洞，它允许攻击者绕过安全启动保护并在启动过程中执行不受信任的代码，从而部署恶意的 UEFI 启动套件，如 Bootkitty 和 BlackLotus。令人震惊的是，即使启用了安全启动，此漏洞也会影响系统。  
  
该缺陷存在于使用 Microsoft 的“Microsoft Corporation UEFI CA 2011”第三方证书签名的 UEFI 应用程序中。该漏洞源于使用自定义 PE 加载程序而不是标准且安全的 UEFI 功能LoadImage和StartImage。  
  
此疏忽允许从系统启动期间命名的特制文件加载未签名的二进制文件cloak.dat，从而完全绕过安全启动完整性检查。  
#### 受影响的软件和供应商  
  
存在漏洞的 UEFI 应用程序集成到多家供应商开发的多个实时系统恢复软件套件中，包括 Howyar Technologies Inc.、Greenware Technologies、Radix Technologies Ltd.、SANFONG Inc.、Wasay Software Technology Inc.、Computer Education System Inc. 和 Signal Computer GmbH。受影响的产品包括：  
- **Howyar SysReturn**  
（10.2.023_20240919 之前的版本）  
  
- **Greenware GreenGuard**  
（10.2.023-20240927 之前的版本）  
  
- **Radix SmartRecovery**  
（11.2.023-20240927 之前的版本）  
  
- **三峰EZ-back系统**  
（10.3.024-20241127之前版本）  
  
- **WASAY eRecoveryRX**  
（8.4.022-20241127 之前的版本）  
  
- **CES NeoImpact**  
（10.1.024-20241127 之前的版本）  
  
- **SignalComputer HDD King**  
（10.3.021-20241127 之前的版本）。  
  
UEFI 安全启动验证通过对照两个数据库检查启动应用程序（如 Windows 启动管理器、shim 或 GRUB2）来确保它们的完整性：db，其中列出平台固件信任的允许证书或 PE Authenticode 哈希；dbx，其中包含禁止的证书或哈希。  
  
启动应用程序必须得到 db 信任并且未在 dbx 中列出，UEFI 启动管理器才能执行它；否则，就会发生安全违规。  
  
ESET报告称，利用 CVE-2024-7344 可让攻击者用 EFI 系统分区 (ESP) 上的恶意二进制文件替换合法的引导加载程序二进制文件。  
  
这允许未签名的代码在早期启动阶段执行，授予攻击者对系统的持久访问权限，同时逃避操作系统级安全工具（如端点检测和响应(EDR) 解决方案）的检测。  
  
将恶意文件部署到 ESP 需要高级权限，例如 Windows 上的本地管理员权限或 Linux 上的根访问权限。  
  
ESET 于 2024 年 6 月向 CERT 协调中心 (CERT/CC) 报告了此漏洞，随后与受影响的供应商协调努力解决此问题。微软在 2025 年 1 月 14 日的补丁星期二更新中撤销了易受攻击的二进制文件。  
  
建议用户通过应用 Microsoft 或其各自操作系统供应商提供的最新 UEFI 撤销来及时更新其系统。  
  
对于 Windows 用户，更新应通过 Windows Update 自动应用。Linux 用户可以通过 Linux 供应商固件服务获取更新。  
  
此事件凸显了人们对第三方 UEFI 软件安全实践以及微软针对 UEFI 应用程序的代码签名过程的更广泛担忧。  
  
发现这种“明显不安全”的签名二进制文件引发了人们的疑问：第三方软件中可能还存在多少未被发现的易受攻击的引导加载程序。  
  
ESET 研究人员呼吁微软在签署第三方 UEFI 应用程序的审查过程中提高透明度，以防止将来出现类似的漏洞。  
  
为了防止潜在的利用：  
1. 对受影响的恢复软件应用所有可用的更新。  
  
1. 确保系统的安全启动禁止签名数据库（DBX）是最新的。  
  
1. 定期审核 UEFI 配置是否存在未经授权的更改。  
  
虽然目前尚未发现任何现实世界的利用尝试，但专家警告说，如果不加以修补，像 CVE-2024-7344 这样的漏洞可能会被复杂的威胁行为者利用。  
  
这一发现强调了强大的固件安全实践和及时的补丁管理对于保护关键系统免受新出现的威胁的重要性。  
  
来源：https://cybersecuritynews.com/uefi-secure-boot-bypass-vulnerability/  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】2024年12月涉国内数据泄露事件汇总](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067407&idx=1&sn=47291e4d3be4fe5aba124eaf42090def&scene=21#wechat_redirect)  
  
  
  
[【安全圈】TikTok计划本周日关停美国业务](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067407&idx=2&sn=c4ea18f86a062710556f1866f61a834d&scene=21#wechat_redirect)  
  
  
  
[【安全圈】超过 660,000 个 Rsync 服务器遭受代码执行攻击](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067407&idx=3&sn=8ab61dc14be99150b80875b0242ba5ee&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Fortinet 又被确认存在新的零日漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652067407&idx=4&sn=0e43cb3c3a8763dcfcbd7b70a9d16464&scene=21#wechat_redirect)  
  
  
  
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
  
  
