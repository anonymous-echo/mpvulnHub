#  黑客利用旧版 ThinkPHP 和 ownCloud 漏洞攻击量激增   
Rhinoer  犀牛安全   2025-03-01 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdFoneckEJLFgEgwEAJTVn2pEEIJ4M7VRw1D11BTDKADN4Ok8N1Eclpw/640?wx_fmt=png&from=appmsg "")  
  
我们发现黑客试图攻击那些容易受到 2022 年和 2023 年旧安全问题影响的维护不善的设备。  
  
威胁监控平台 GreyNoise 报告称，利用   
CVE-2022-47945  
和  
CVE-2023-49103  
的攻击行为者数量激增 ，这会影响 ThinkPHP 框架和用于文件共享和同步的开源 ownCloud 解决方案。  
  
这两个漏洞的严重性都很高，可以利用它们来执行任意操作系统命令或获取敏感数据（例如管理员密码、邮件服务器凭据、许可证密钥）。  
  
第一个漏洞是 ThinkPHP Framework 6.0.14 之前版本语言参数中的一个本地文件包含（LFI）问题。未经身份验证的远程攻击者可利用该漏洞在启用了语言包功能的部署环境中执行任意操作系统命令。  
  
Akamai去年夏天  
报道称  
，某国攻击为者自 2023 年 10 月以来一直在小范围行动中利用该漏洞。  
  
据威胁监测平台 GreyNoise 称，CVE-2022-47945 目前正受到大量利用，发起攻击的源 IP 越来越多。  
  
公告警告称  
：“GreyNoise 已观察到 572 个唯一 IP 试图利用此漏洞，且最近几天活动有所增加。”  
  
尽管该漏洞的漏洞预测评分系统 (EPSS) 评分较低 (7%)，且未包含在 CISA 的已知利用漏洞 (KEV) 目录中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdvfBedIKPVx2dKrlT1cTgyj1ypaXs0cG3Evh4EZcYECGdvsLI5A3giaA/640?wx_fmt=png&from=appmsg "")  
  
第二个漏洞影响流行的开源文件共享软件，源于该应用程序对通过 URL 公开 PHP 环境详细信息的第三方库的依赖。  
  
2023 年 11 月开发人员首次披露该漏洞后不久，黑客就开始利用该漏洞从未修补的系统中窃取敏感信息。  
  
一年后，CVE-2023-49103被 FBI、CISA 和 NSA列为2023 年 15 个最容易被利用的漏洞之一。  
  
尽管自供应商发布解决安全问题的更新以来已经过去了两年多，但许多实例仍然未得到修补并暴露在攻击之下。  
  
GreyNoise 最近发现 CVE-2023-49103 的利用率有所增加，恶意活动源自 484 个唯一 IP。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlEq1M1v6OCBuknjZQcg1BdcPkheFM3X95FkXWkNrXveTe412NibFCsqNnYAl6mohE05wiaaDnZPrTg/640?wx_fmt=png&from=appmsg "")  
  
为了保护系统免遭主动攻击，建议用户升级到 ThinkPHP 6.0.14 或更高版本，并将 ownCloud GraphAPI 升级到 0.3.1 及更新版本。  
  
还建议将潜在的易受攻击的实例脱机或置于防火墙后面，以减少攻击面。  
  
  
信息来源：BleepingComputer  
  
