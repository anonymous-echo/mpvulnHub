#  新的 UEFI 安全启动严重漏洞，请立即修补   
Rhinoer  犀牛安全   2025-01-31 16:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczQkUSxKwl2WbCfuCJB2fQpJhhx4nQhIjk6LDXCXC4ToAcFNNz7leHIQ/640?wx_fmt=png&from=appmsg "")  
  
一个新的 UEFI 安全启动绕过漏洞 ( CVE-2024-7344) 影响 Microsoft 签名的应用程序，即使安全启动保护处于活动状态，该漏洞也可能被利用来部署启动工具包。  
  
存在漏洞的 UEFI 应用程序存在于多家第三方软件开发商的多种实时系统恢复工具中。  
  
Bootkit 代表着一种严重的安全威胁，由于它们在操作系统加载之前采取行动，并且在操作系统重新安装后仍然存在，因此很难被发现。  
  
潜在问题  
  
该问题源于应用程序使用自定义 PE 加载器，它允许加载任何 UEFI 二进制文件，即使它们未经签名。  
  
具体来说，存在漏洞的 UEFI 应用程序不依赖于“LoadImage”和“StartImage”等可信服务，这些服务会根据信任数据库 (db) 和撤销数据库 (dbx) 来验证二进制文件。  
  
在这种情况下，“reloader.efi”会手动解密“cloak.dat”中的二进制文件并将其加载到内存中，其中包含基本的加密 XOR PE 图像。  
  
攻击者可以利用这个不安全的过程，用存在漏洞的“reloader.efi”替换 EFI 分区上应用程序的默认操作系统引导加载程序，并在其标称路径上植入恶意的“cloak.dat”文件。  
  
在系统启动时，自定义加载程序将在没有安全启动验证的情况下解密并执行恶意二进制文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmHhbBXfQiamrop040eReAczHRlAJ4RgJkNxk2U5yZJZ7lapWHTeSvygyrEjnADpP0Ptdul8F9ajMg/640?wx_fmt=png&from=appmsg "")  
  
影响范围  
  
该漏洞影响旨在协助系统恢复、磁盘维护或备份的 UEFI 应用程序，而不是通用的 UEFI 应用程序。  
  
ESET 的报告 列出了以下存在漏洞的产品和版本：   
- Howyar SysReturn 10.2.023_20240919 之前的版本  
  
- Greenware GreenGuard 10.2.023-20240927 之前的版本  
  
- Radix SmartRecovery 11.2.023-20240927 之前的版本  
  
- 三峰EZ-back系统10.3.024-20241127之前版本  
  
- WASAY eRecoveryRX 8.4.022-20241127 之前的版本  
  
- CES NeoImpact 10.1.024-20241127 之前版本  
  
- SignalComputer HDD King 10.3.021-20241127 之前版本  
  
需要注意的是，即使目标计算机上没有上述应用程序，攻击者也可能利用 CVE-2024-7344。黑客只需部署这些应用程序中易受攻击的“reloader.efi”二进制文件即可执行攻击。  
  
然而，使用上述应用程序和受影响版本的用户应尽快迁移到较新的版本，以消除攻击面。  
## 修复和缓解措施  
  
Microsoft 已发布针对 CVE-2024-7344 的补丁  
  
ESET 于 2024 年 7 月 8 日发现该漏洞，并  
报告  
给 CERT 协调中心（CERT/CC），以便向受影响方协调披露。  
  
受影响的供应商已在其产品中修复了该问题，微软 已于 1 月 14 日补丁星期二更新中  
撤销了证书  
  
在接下来的几个月里，ESET 与受影响的供应商合作评估提议的补丁并消除安全问题。  
  
最终，在 2025 年 1 月 14 日，微软  
撤销了存在漏洞的 UEFI 应用程序的证书  
，这将阻止任何执行其二进制文件的尝试。  
  
此缓解措施会自动应用于安装了最新 Windows 更新的用户。ESET 还分享了 PowerShell 命令，关键系统的管理员可以使用这些命令手动检查撤销是否已成功应用。  
  
  
信息来源：  
BleepingComputer  
  
