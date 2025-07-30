#  【安全圈】Adobe 紧急发布安全更新，修复十二款产品多项漏洞   
 安全圈   2025-04-10 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliaSxaDVehkuSHcKanYW1nJBOevlLmLjXbicRujlW2lBsrb3jHDX2myoV8T9acFAby5sq3Kt0C1xZVg/640?wx_fmt=png&from=appmsg "")  
  
Adobe 已发布了一套全面的安全更新，用于修复旗下十二款产品中存在的多个漏洞。  
  
这些补丁均于 2025 年 4 月 8 日发布，旨在解决严重、重要及中等程度的安全缺陷，这些缺陷可能会使用户面临各种网络威胁，包括任意代码执行、权限提升以及应用程序拒绝服务攻击。  
  
**已修复的重大漏洞**  
  
**1.Adobe ColdFusion（APSB25-15）**  
  
ColdFusion 的更新修复了多个漏洞，包括不当的输入验证（CVE-2025-24446）、不可信数据的反序列化（CVE-2025-24447）以及不当的访问控制（CVE-2025-30281）。  
  
其他漏洞，如操作系统命令注入（CVE-2025-30286）和跨站脚本攻击（CVE-2025-30292）也得到了解决。  
  
这些漏洞可能会导致任意代码执行、权限提升或敏感信息泄露。  
  
**2.Adobe After Effects（APSB25-23）**  
  
After Effects 的更新修复了诸如内存泄漏和应用程序拒绝服务等严重漏洞。  
  
如果被成功利用，可能会在已登录用户的环境中执行任意代码。受影响的版本包括 24.6.4 及更早版本，以及 Windows 和 macOS 系统上的 25.1 版本。  
  
**3.Adobe Media Encoder（APSB25-24）**  
  
Media Encoder 的更新修复了两个严重漏洞：越界写入（CVE-2025-27194）和基于堆的缓冲区溢出（CVE-2025-27195）。  
  
这些漏洞可能会导致任意代码执行，通用漏洞评分系统（CVSS）评分为 7.8。  
  
**4.Adobe Bridge（APSB25-25）**  
  
Bridge 的安全补丁修复了一个基于堆的缓冲区溢出漏洞（CVE-2025-27193），该漏洞可能会导致任意代码执行。  
  
此漏洞影响 Windows 和 macOS 平台上的 14.1.5 及更早版本，以及 15.0.2 版本。  
  
**5.Adobe Commerce（APSB25-26）**  
  
Adobe Commerce 和 Magento 开源版收到了安全更新，以修复可能导致安全功能绕过、权限提升和应用程序拒绝服务的漏洞。  
  
受影响的版本包括所有平台上的 Adobe Commerce 2.4.8-beta2 及更早版本、Adobe Commerce B2B 1.5.1 及更早版本，以及 Magento 开源版 2.4.8-beta2 及更早版本。  
  
**6.Adobe Experience Manager Forms（APSB25-27）**  
  
AEM Forms 的更新修复了路径遍历（CVE-2024-38819）和区分大小写匹配异常漏洞（CVE-2024-38820）。  
  
这些漏洞源于对第三方组件的依赖，可能会导致未经授权的访问或数据泄露。  
  
**7.Adobe Premiere Pro（APSB25-28）**  
  
Premiere Pro 的更新修复了一个严重的基于堆的缓冲区溢出漏洞（CVE-2025-27196），该漏洞可能会导致受影响的 24.6.4 及更早版本，以及 Windows 和 macOS 系统上的 25.1 版本中执行任意代码。  
  
**8.Adobe Photoshop（APSB25-30）**  
  
Photoshop 的补丁修复了一个基于堆的缓冲区溢出漏洞（CVE-2025-27198），被评定为严重级别，CVSS 评分为 7.8。  
  
如果该漏洞被成功利用，可能会导致任意代码执行。  
  
**9.Adobe Animate（APSB25-31）**  
  
Adobe Animate 的更新修复了严重漏洞，如基于堆的缓冲区溢出（CVE-2025-27199）和释放后使用（CVE-2025-27200），这两个漏洞的 CVSS 评分均为 7.8，可能会导致任意代码执行。  
  
此外，还修复了两个内存泄漏漏洞（CVE-2025-27201 和 CVE-2025-27202），评定为重要级别，CVSS 评分为 5.5。这些漏洞影响 Windows 和 macOS 平台上的 Adobe Animate 2023（23.0.10 及更早版本）和 2024（24.0.7 及更早版本）。  
  
**10.Adobe Experience Manager Screens（APSB25-32）**  
  
Adobe Experience Manager（AEM）Screens 的更新修复了一个与反射型跨站脚本攻击（XSS）相关的重要漏洞（CVE-2025-27205）。  
  
此漏洞的 CVSS 评分为 5.4，如果被成功利用，可能会导致任意代码执行。它影响所有平台上直至 AEM 6.5 Screens FP11.3 的 AEM Screens 版本。  
  
**11.Adobe FrameMaker（APSB25-33）**  
  
FrameMaker 的更新修复了几个严重漏洞，包括越界写入（CVE-2025-30304）、基于堆的缓冲区溢出（CVE-2025-30295）和基于栈的缓冲区溢出（CVE-2025-30298）。  
  
这些问题可能会让攻击者执行任意代码或导致应用程序崩溃。  
  
**12.Adobe XMP Toolkit SDK（APSB25-34）**  
  
XMP Toolkit SDK 的更新修复了多个越界读取漏洞（例如，CVE-2025-30305 至 CVE-2025-30309）。  
  
利用这些漏洞可能会导致信息泄露或应用程序不稳定。安全专家建议所有受影响的 Adobe 产品用户立即更新其安装的软件。对于大多数产品，可以通过 Creative Cloud 桌面应用程序的更新机制进行更新，或者在各个应用程序中进入 “帮助” 菜单并选择 “更新”。对于托管环境，IT 管理员可以使用 Creative Cloud Packager 创建部署包。  
  
Adobe 已确认，目前尚未发现这些漏洞在现实中被利用的情况。然而，及时打补丁对于维护 Adobe 创意和企业产品生态系统的安全完整性仍然至关重要。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】谷歌紧急发布4月安全更新 修复62个Android漏洞含两大零日漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068976&idx=1&sn=60a9f88e02e487944d15429688fbd7f6&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Adobe 修复了 11 个 ColdFusion 严重漏洞，共发现 30 个漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068976&idx=2&sn=9430325038d82c9d54b40e83a162b8e8&scene=21#wechat_redirect)  
  
  
  
[【安全圈】假冒 Microsoft Office 插件工具通过 SourceForge 推送恶意软件](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068976&idx=3&sn=f9111a0c6b1ffd4f0343440dd3e28f00&scene=21#wechat_redirect)  
  
  
  
[【安全圈】#DeepSeek又崩了#](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068959&idx=1&sn=e9b5f893828331429dcbf677edf57f8b&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
