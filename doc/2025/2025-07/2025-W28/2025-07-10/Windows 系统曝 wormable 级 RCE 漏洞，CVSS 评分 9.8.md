> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458597040&idx=2&sn=cdca0a3babe6585f09000478395ba7bf

#  Windows 系统曝 wormable 级 RCE 漏洞，CVSS 评分 9.8  
看雪学苑  看雪学苑   2025-07-10 10:05  
  
微软于2025年7月8日发布关键安全更新，以解决 CVE-2025-47981 漏洞。这是一个在 SPNEGO 扩展协商（NEGOEX）安全机制中存在的严重堆缓冲区溢出漏洞，影响多个 Windows 客户端和服务器版本。  
  
  
该漏洞的 CVSS 评分为 9.8 分（满分 10 分），属于最高严重级别，可能导致无需用户交互的远程代码执行。其被归类为 CWE-122，即堆基于缓冲区溢出弱点，可被远程利用。从 CVSS 向量字符串来看，这是一种基于网络的攻击，复杂性低，无需特权或用户交互，却会对机密性、完整性和可用性造成高影响。  
  
  
安全研究人员评估此漏洞 “更可能被利用”，不过在披露时，尚未有公开利用程序或活跃利用的报告。此漏洞对运行 Windows 10 1607 及以上版本的客户端机器影响尤为明显，因为这些机器上 “网络安全：允许对此计算机的 PKU2U 身份验证请求使用在线身份” 这一组策略对象默认处于启用状态。  
  
  
攻击者可通过向受影响的服务器发送恶意消息来利用该漏洞，有可能获得远程代码执行能力。堆缓冲区溢出发生在 NEGOEX 处理机制内，使攻击者能够覆盖内存结构并控制程序执行流程。这种 wormable 特性意味着该漏洞可能在联网系统间传播，无需用户干预。  
  
  
受影响的产品众多，涵盖 Windows 10（1607 及以上版本）、Windows 11（23H2、24H2 版本）、Windows Server 2008 R2 至 Server 2025，包括 x64、x86 和 ARM64 架构以及 Server Core 安装。  
  
  
此次发布的安全更新针对不同 Windows 配置，包括 Windows Server 2025（版本 10.0.26100.4652）、Windows 11 24H2 版本（版本 10.0.26100.4652）、Windows Server 2022 23H2 版本（版本 10.0.25398.1732）以及包括 Windows Server 2008 R2（版本 6.1.7601.27820）在内的 legacy 系统。  
  
  
各组织应优先立即部署这些安全更新，尤其是面向互联网的系统和域控制器。补丁可通过 Windows Update、微软更新目录和 Windows Server Update Services（WSUS）获取。  
  
  
  
资讯来源：  
cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
