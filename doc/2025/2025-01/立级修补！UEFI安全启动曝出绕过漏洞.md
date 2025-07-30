#  立级修补！UEFI安全启动曝出绕过漏洞   
 GoUpSec   2025-01-17 02:19  
  
UEFI Secure Boot一直被视为保障系统启动安全的关键防线和“底线”。然而，近期发现的一个严重漏洞（CVE-2024-7344），却让这一防线面临重大挑战。该漏洞影响一个由微软签名的应用程序，攻击者可利用其部署启动工具包（bootkits），即使在Secure Boot保护激活的情况下也不例外。  
  
  
**漏洞详情**  
  
  
**1**  
  
  
**受影响的UEFI应用**  
  
  
该漏洞涉及的UEFI应用广泛存在于多个实时系统恢复工具中，这些工具由多个第三方软件开发商提供。这些应用原本旨在协助系统恢复、磁盘维护或备份，却因安全漏洞而成为攻击者的突破口。  
  
  
**2**  
  
  
**漏洞成因**  
  
  
问题根源在于该UEFI应用使用了自定义的PE加载器，这使得加载任何UEFI二进制文件成为可能，即使这些文件未经过签名。具体来说，该应用未依赖于可信服务，如“LoadImage”和“StartImage”，这些服务会验证二进制文件是否符合信任数据库（db）和撤销数据库（dbx）的要求。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvYrOBaqxyd3EGj2OpcP0zHV8u5dATJfJoIVvPTpqMaMibB9kU02cGza5ico1uFbQ6kRjUe2AXT4l3zw/640?wx_fmt=png&from=appmsg "")  
  
UEFI安全启动流程 来源：ESET  
  
  
**3**  
  
  
**攻击手法**  
  
  
攻击者可利用这一漏洞，通过替换应用的默认操作系统引导加载程序，将易受攻击的“reloader.efi”和恶意的“cloak.dat”文件植入EFI分区的指定路径。系统启动时，自定义加载器会解密并执行恶意二进制文件，而无需Secure Boot验证。  
  
  
**影响范围**  
  
  
**1**  
  
  
**受影响产品及版本**  
  
  
ESET的报告列出了以下易受攻击的产品和版本：  
  
- Howyar SysReturn 10.2.023_20240919之前的版本  
  
- Greenware GreenGuard 10.2.023-20240927之前的版本  
  
- Radix SmartRecovery 11.2.023-20240927之前的版本  
  
- Sanfong EZ-back System 10.3.024-20241127之前的版本  
  
- WASAY eRecoveryRX 8.4.022-20241127之前的版本  
  
- CES NeoImpact 10.1.024-20241127之前的版本  
  
- Signal Computer HDD King 10.3.021-20241127之前的版本  
  
  
  
**2**  
  
  
**潜在攻击风险**  
  
  
值得注意的是，即使上述应用未安装在目标计算机上，攻击者仍可利用CVE-2024-7344，只需部署易受攻击的“reloader.efi”二进制文件即可。因此，使用上述应用且受影响版本的用户应尽快升级至最新版本，以消除攻击面。  
  
  
**修复与缓解措施**  
  
  
**1**  
  
  
**微软补丁**  
  
  
微软已于2025年1月14日的Patch Tuesday更新中发布了CVE-2024-7344的补丁。ESET于2024年7月8日发现该漏洞，并向CERT协调中心（CERT/CC）报告，以便与受影响方进行协调披露。  
  
  
**2**  
  
  
**受影响厂商的修复**  
  
  
受影响的厂商已在产品中修复了该问题，微软也在同日的更新中撤销了易受攻击的UEFI应用的证书。在接下来的几个月里，ESET与受影响的厂商合作，评估提议的补丁并消除安全问题。  
  
  
**3**  
  
  
**自动与手动检查**  
  
  
2025年1月14日，微软撤销了易受攻击的UEFI应用的证书，这应阻止任何尝试执行其二进制文件的行为。此缓解措施会自动应用于安装了最新Windows更新的用户。ESET还分享了PowerShell命令，供关键系统管理员手动检查撤销是否已成功应用。  
  
  
**事件反思与行业警示**  
  
  
此次UEFI Secure Boot绕过漏洞的发现，凸显了第三方UEFI软件安全实践和微软UEFI应用程序代码签名过程中的更广泛问题。ESET研究人员呼吁微软在其审查第三方UEFI应用程序签名的过程中提高透明度，以防止未来出现类似漏洞。这一事件提醒我们，即使是被视为关键安全功能的UEFI Secure Boot，也不是牢不可破的屏障。企业和组织必须保持高度警惕，及时更新和审查安全措施，以应对不断演变的网络威胁态势。  
  
  
参考链接：  
- https://www.welivesecurity.com/en/eset-research/under-cloak-uefi-secure-boot-introducing-cve-2024-7344/  
  
- https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-7344  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/INYsicz2qhvZRDUnojiaba5EGXQ7vEkEX8iar6wfVEW8pJj4v4XBgG48Lt1Ga5seakLRcfZJdGmq4yUsZXdLh2ZfA/640?wx_fmt=other "")  
  
  
END  
  
  
  
相关阅读  
  
  
  
[网络安全不是一场漏洞游戏](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247502111&idx=1&sn=b0f654dd8dca96c65c35560724d44825&scene=21#wechat_redirect)  
  
  
[锐捷网络云管理平台爆出严重漏洞，可从云端劫持WiFi热点](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501914&idx=2&sn=1c6de3ff616e3417b47a78f7ba17bed3&scene=21#wechat_redirect)  
  
  
[CVSS漏洞评分系统曝出严重缺陷](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501831&idx=2&sn=d46f09ca7bcd0bbb103e627313a165fb&scene=21#wechat_redirect)  
  
  
[MITRE公布最危险软件漏洞TOP25榜单](https://mp.weixin.qq.com/s?__biz=MzkxNTI2MTI1NA==&mid=2247501504&idx=2&sn=741da5d8dcc2e08936f21c432a3b1f0e&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/INYsicz2qhvbgcN4QY36lK2wjCavZiadQThpmM11FR4xkwyVG7K24lkpoLRcFHuZ7gAHgZEsr6Mia7BmKuwDJqX4g/640?wx_fmt=jpeg "")  
  
