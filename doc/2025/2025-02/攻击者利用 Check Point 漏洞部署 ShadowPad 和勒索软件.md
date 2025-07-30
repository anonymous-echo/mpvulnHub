#  攻击者利用 Check Point 漏洞部署 ShadowPad 和勒索软件   
会杀毒的单反狗  军哥网络安全读报   2025-02-21 01:01  
  
**导****读**  
  
  
  
一个此前未知的威胁活动集群针对欧洲组织，特别是医疗保健组织，部署 PlugX 及其后继产品 ShadowPad，而在某些情况下，这些入侵最终导致部署名为 NailaoLocker 的勒索软件。  
  
  
该活动代号为 Green Nailao，涉及利用 Check Point 网络网关安全产品中新修补的安全漏洞（CVE-2024-24919，CVSS 评分：7.5）。攻击发生在 2024 年 6 月至 10 月之间。  
  
  
该公司在一份技术报告中表示： “该活动依靠 DLL 劫持来部署 ShadowPad 和 PlugX——这两种植入程序通常与某个黑客团体有关。”  
  
  
据称，利用存在漏洞的 Check Point 实例所获得的初始访问权限允许攻击者检索用户凭据并使用合法帐户连接到 VPN。  
  
  
在下一阶段，攻击者通过远程桌面协议 (RDP) 进行网络侦察和横向移动以获取提升的权限，然后执行合法二进制文件 (“logger.exe”) 来侧载恶意 DLL (“logexts.dll”)，然后将其用作新版本ShadowPad恶意软件的加载器。  
  
  
研究发现，2024 年 8 月检测到的攻击的先前版本利用类似的手段来传播PlugX，该攻击也使用 DLL 侧加载，使用 McAfee 可执行文件（“mcoemcpy.exe”）来侧加载“McUtil.dll”。  
  
  
与 PlugX 一样，ShadowPad 是一种私人销售的恶意软件，至少自 2015 年以来一直由某黑客团体独家使用。Orange Cyber  
  
defense CERT 发现的变体具有复杂的混淆和反调试措施，同时与远程服务器建立通信以创建对受害者系统的持久远程访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGaRPXk4iaec1qJOzRrlCS5mdIYhXdq00d38Tib3YnNy9VvickibkyBObba5O1aRSUtgxLxho9lD71AWg/640?wx_fmt=png&from=appmsg "")  
  
NailaoLoader和NailaoLocker的执行流程  
  
  
有证据表明，攻击者试图通过访问文件系统并创建 ZIP 存档来窃取数据。入侵最终使用 Windows 管理规范 (WMI) 传输三个文件，一个由合法公司签名的可执行文件（“usysdiag.exe”）、一个名为 NailaoLoader 的加载程序（“sensapi.dll”）和 NailaoLocker（“usysdiag.exe.dat”）。  
  
  
再次，DLL 文件通过“usysdiag.exe”侧载，以解密并触发 NailaoLocker 的执行，NailaoLocker 是一种基于 C++ 的勒索软件，它会加密文件，在文件后附加“.locked”扩展名，并放置一张勒索信，要求受害者支付比特币或通过 Proton Mail 地址联系他们。  
  
  
研究人员 Marine Pichon 和 Alexis Bonnefoi 表示：“NailaoLocker 相对不太复杂，设计也很差，似乎无法保证完全加密。”  
  
  
“它不会扫描网络共享，不会停止可能阻止某些重要文件加密的服务或进程，[并且]它不会控制是否正在被调试。”  
  
  
由于此次攻击使用了 ShadowPad 植入程序和 DLL 侧载技术，且类似的勒索软件计划已被归咎于另一个名为Bronze Starlight的威胁组织。  
  
  
虽然此次间谍兼勒索软件活动的具体目标尚不清楚，但人们怀疑威胁组织正在寻求快速获利。  
  
  
研究人员表示：“这可能有助于解释 ShadowPad 和 NailaoLocker 之间的复杂程度差异，NailaoLocker 有时甚至会尝试模仿 ShadowPad 的加载技术。  
  
  
虽然此类活动有时是随机进行的，但它们通常允许威胁团体访问信息系统，随后可用于进行其他攻击行动。”  
  
  
新闻链接：  
  
https://thehackernews.com/2025/02/chinese-linked-attackers-exploit-check.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
