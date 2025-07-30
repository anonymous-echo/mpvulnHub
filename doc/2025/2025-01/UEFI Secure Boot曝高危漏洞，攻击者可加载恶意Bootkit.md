#  UEFI Secure Boot曝高危漏洞，攻击者可加载恶意Bootkit   
Hankzheng  技术修道场   2025-01-26 01:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT4ic1pMvZT4oS46tMXyGGD2c1fLFjDRZchnuCc8FNqzEhj86WmMhe1IDicibb1h77QhYWUgCIcpUWXicEw/640?wx_fmt=png&from=appmsg "")  
  
近日，网络安全研究人员披露了一个已修复的高危漏洞（CVE-2024-7344，CVSS评分：6.7），该漏洞允许攻击者绕过UEFI（统一可扩展固件接口）系统中的Secure Boot机制，加载恶意启动工具包（Bootkit）。这一漏洞由ESET研究人员发现，并已向CERT协调中心（CERT/CC）报告。微软在2025年1月的“补丁星期二”更新中撤销了受影响的二进制文件。  
  
**漏洞详情**  
  
该漏洞存在于由微软“Microsoft Corporation UEFI CA 2011”第三方UEFI证书签名的UEFI应用程序中。攻击者利用该漏洞可以在系统启动期间执行不受信任的代码，从而在启用Secure Boot的设备上部署恶意UEFI Bootkit，无论设备安装的是何种操作系统。  
  
Secure Boot是一种固件安全标准，旨在通过验证加载代码的真实性、来源和完整性，防止计算机启动时加载恶意软件。然而，受影响的UEFI应用程序使用了自定义的PE加载器，而非标准的UEFI函数LoadImage  
和StartImage  
，导致其允许从名为cloak.dat  
的特制文件中加载任何UEFI二进制文件（包括未签名的文件），从而绕过Secure Boot保护。  
  
**受影响产品**  
  
以下实时系统恢复软件套件中的UEFI应用程序受到该漏洞影响：  
- Howyar SysReturn（10.2.023_20240919之前版本）  
  
- Greenware GreenGuard（10.2.023-20240927之前版本）  
  
- Radix SmartRecovery（11.2.023-20240927之前版本）  
  
- Sanfong EZ-back System（10.3.024-20241127之前版本）  
  
- WASAY eRecoveryRX（8.4.022-20241127之前版本）  
  
- CES NeoImpact（10.1.024-20241127之前版本）  
  
- SignalComputer HDD King（10.3.021-20241127之前版本）  
  
**潜在危害**  
  
成功利用该漏洞的攻击者可以在操作系统加载之前，在UEFI上下文中执行未签名代码，从而获得对主机的隐蔽持久访问权限。CERT/CC指出，在此早期启动阶段执行的代码可以持久存在于系统中，加载恶意内核扩展，甚至在系统重启和操作系统重新安装后仍然存在。此外，此类攻击可能规避基于操作系统的安全措施和端点检测与响应（EDR）工具的检测。  
  
**修复建议**  
  
微软已于2025年1月14日撤销了受影响的二进制文件。为防范类似漏洞，建议采取以下措施：  
1. **应用UEFI撤销列表**  
：确保系统加载的UEFI二进制文件未被撤销。  
  
1. **管理EFI系统分区访问权限**  
：限制对EFI系统分区文件的访问，防止恶意文件部署。  
  
1. **启用远程证明**  
：结合可信平台模块（TPM）使用远程证明功能，验证系统启动完整性。  
  
1. **及时更新固件**  
：定期检查并安装设备制造商发布的固件更新。  
  
**专家观点**  
  
ESET研究员Martin Smolár表示：“近年来发现的UEFI漏洞数量以及修复或撤销漏洞二进制文件的延迟表明，即使是UEFI Secure Boot这样的核心功能也不应被视为不可逾越的屏障。更令人担忧的是，这并非首次发现明显不安全的签名UEFI二进制文件，这引发了对第三方UEFI软件供应商使用此类不安全技术的普遍性以及可能存在其他类似漏洞的疑问。”  
  
**结语：**  
  
此次漏洞的披露再次提醒我们，UEFI Secure Boot并非绝对安全。企业和个人用户应保持警惕，及时应用安全更新，并采取多层次防护措施，以应对日益复杂的固件级威胁。  
  
