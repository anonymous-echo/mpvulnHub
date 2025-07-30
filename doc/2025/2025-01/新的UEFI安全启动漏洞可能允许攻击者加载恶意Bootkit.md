#  新的UEFI安全启动漏洞可能允许攻击者加载恶意Bootkit   
跳舞的花栗鼠  FreeBuf   2025-01-17 11:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
新发现的漏洞CVE-2024-73  
44被认定为UEFI安全启动机制中的一个严重缺陷，可能会影响大多数基于UEFI的系统。该漏洞由ES  
ET的研究人员发现，允许攻击者绕过安全启动保护，在启动过程中执行不受信任的代码，从而部署像Bootkitty和BlackLotus这样的恶意UEFI启动套件。令人震惊的是，即使启用了安全  
启动，该漏洞也会影响系统。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CJILCF0N7ojic1yGnZkR4cqKF47TV1WLMurQ0J4tAYDanQEdXnfSO2lxMWObT6U7Y6iaicibqDsWOvg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞存在于使用微软“Microsoft Corporation UEFI CA 2011”第三方证书签名的UEFI应用程序中。漏洞源于使用自定义PE加载器，而不是标准且安全的UEFI函数LoadImage和StartImage。这一疏忽允许在系统启动期间，从一个特制的名为cloak.dat的文件中加载未签名的二进制文件，从而完全绕过安全启动完整性检查。  
  
  
**受影响的软件和供应商**  
  
  
  
该易受攻击的UEFI应用程序被集成到多个供应商开发的实时系统恢复软件套件中，包括 Howyar Technologies Inc.、Greenware Technologies、Radix Technologies Ltd.、SANFONG Inc.、Wasay Software Technology Inc.、Computer Education System Inc. 和 Signal Computer GmbH。  
  
  
**受影响的产品包括：**  
- Howyar SysReturn（10.2.023_20240919 之前的版本）  
  
- Greenware GreenGuard（10.2.023-20240927 之前的版本）  
  
- Radix SmartRecovery（11.2.023-20240927 之前的版本）  
  
- 三峰EZ-back系统（10.3.024-20241127之前版本）  
  
- WASAY eRecoveryRX（8.4.022-20241127 之前的版本）  
  
- CES NeoImpact（10.1.024-20241127 之前的版本）  
  
- SignalComputer HDD King（10.3.021-20241127 之前的版本）  
  
UEFI安全启动验证通过比对两个数据库，检查启动应用程序（如Windows启动管理器、shim或GRUB2）来确保其完整性。db数据库，列出了平台固件信任的允许证书或PE Authenticode哈希；dbx数据库，包含被禁止的证书或哈希。启动应用程序必须被db信任且未被列入dbx，UEFI启动管理器才会执行它；否则，就会发生安全违规。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38CJILCF0N7ojic1yGnZkR4chzWEkvkaVWJcIkyjf3B5kcvMd1PiaedwbcWdS4xOteRe6BxSWSpaQpQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
ESET报告称，利用CVE-2024-7344，攻击者可以在EFI系统分区（ESP）上用恶意的引导加载程序二进制文件替换合法的文件。这使得未签名的代码能够在早期启动阶段执行，从而授予攻击者持久的系统访问权限，同时规避如EDR这种操作系统级别的安全工具的检测。  
  
  
在ESP上部署恶意文件需要提升的权限，如Windows上的本地管理员权限或Linux上的root访问权限。2024年6月ESET向CERT协调中心 (CERT/CC) 报告了此漏洞，随后与受影响的供应商协调努力解决该问题。微软在2025年1月14日的Patch Tuesday更新中撤销了易受攻击的二进制文件。  
  
  
**解决措施与防范建议**  
  
  
  
建议用户通过应用微软或各自操作系统供应商提供的最新UEFI撤销更新，及时更新系统。对于Windows用户，更新应通过Windows Update自动应用。Linux用户可以通过Linux供应商固件服务获取更新。  
  
  
这一事件凸显了对第三方UEFI软件安全实践的广泛担忧，同时还引发了对微软UEFI应用程序代码签名流程的担忧。发现这种“明显不安全”的签名二进制文件引发了人们的疑问：第三方软件中可能还存在多少未被发现的易受攻击的引导程序问题？  
  
  
ESET研究人员呼吁微软在签署第三方UEFI应用程序的过程中，提高审查的透明度，以防止未来出现类似的漏洞。  
  
  
**为防止潜在的利用，建议采取以下措施：**  
- 应用所有受影响恢复软件的可用更新。  
  
- 确保系统的安全启动禁止签名数据库（DBX）是最新的。  
  
- 定期审核UEFI配置，检查是否存在未经授权的更改。  
  
尽管目前尚未检测到实际的利用尝试，但专家警告称，如果未及时修补，像CVE-2024-7344这样的漏洞可能会被复杂的威胁行为者武器化。  
  
  
这一发现强调了强大的固件安全实践，以及及时补丁管理的重要性。这两者对于保护关键系统免受新兴威胁都至关重要。  
  
   
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
