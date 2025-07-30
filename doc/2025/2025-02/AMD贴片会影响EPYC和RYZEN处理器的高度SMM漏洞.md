#  AMD贴片会影响EPYC和RYZEN处理器的高度SMM漏洞   
 Ots安全   2025-02-16 12:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taegB05Ve4ZIB108iaBNHv7LIiasXvIqqDywrkCPrwrEawZQE3j3ENrLueh4F85A5kWsRrGaxYEuyyNQ/640?wx_fmt=png&from=appmsg "")  
  
AMD 发布了安全补丁，修复了影响其系统管理模式 (SMM) 的两个高严重性漏洞。SMM 是 AMD 处理器固件中的特权执行环境。如果利用这些漏洞，特权攻击者可以执行任意代码，并可能损害系统完整性。  
  
这些漏洞的编号为 CVE-2024-0179 和 CVE-2024-21925，CVSS 评分均为 8.2（高）。据 AMD 称，这些漏洞由 Quarkslab 报告，影响多代 AMD EPYC 和 Ryzen 处理器。  
  
CVE-2024-0179 是 AmdCpmDisplayFeatureSMM UEFI 模块中的 SMM Callout 漏洞。AMD警告称，此问题“可能允许本地认证的攻击者覆盖 SMRAM，从而可能导致任意代码执行”。  
  
CVE-2024-21925 源于 AmdPspP2CmboxV2 UEFI 模块中的输入验证不足，这可能允许特权攻击者覆盖 SMRAM，从而导致任意代码执行。  
  
这两个漏洞都利用了系统管理 RAM (SMRAM)，这是 SMM 处理程序使用的关键内存区域，旨在与未经授权的访问隔离。具有所需权限的攻击者可以升级其访问权限，以在 ring-0（最高级别的系统权限）上执行恶意负载。  
  
这些漏洞影响多个处理器系列，其中包括：  
  
第一代至第四代 AMD EPYC 处理器（Naples, Rome, Milan, Genoa）  
- AMD Ryzen 5000/7000 系列台式机和移动处理器  
  
- AMD Ryzen Threadripper PRO 和高端台式机 (HEDT) 处理器  
  
- AMD Instinct MI300A 数据中心 GPU  
  
- AMD 感谢Quarkslab的 Gabrielle Viala负责任地披露这些问题。  
  
据 AMD 称，缓解措施需要对平台初始化 (PI) 固件进行固件更新。该公司已为受影响的处理器提供了特定的固件版本，包括 Naples PI 1.0.0.N (2024-09-17)、Rome PI 1.0.0.K (2024-09-05) 和 Milan PI 1.0.0.E (2024-09-05)。  
  
为了解决这些安全风险，AMD 建议用户通过 OEM 供应商更新固件。该公司指出，补丁已集成到 BIOS 更新中，以缓解固件级别的漏洞。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
