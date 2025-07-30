> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458596252&idx=3&sn=3870fcc4fac639f2b1fa7dc71dcbdf97

#  NVIDIA Megatron LM 重大漏洞曝光，攻击者可注入恶意代码，用户需立即升级  
看雪学苑  看雪学苑   2025-06-25 09:59  
  
NVIDIA 公司旗下的 Megatron LM 大型语言模型框架被曝存在严重安全漏洞，攻击者可借此注入恶意代码，进而获取未授权的系统访问权限，引发了一系列严重的安全隐患。2025年6月24日，NVIDIA 紧急发布了安全补丁，以应对影响该框架所有版本（0.12.0 之前的版本）的两个高危漏洞。  
  
  
漏洞概述  
  
此次发现的两个高危代码注入漏洞分别为 CVE-2025-23264 和 CVE-2025-23265，它们在 CVSS 评分体系中的得分为7.8，属于高危风险级别。这两个漏洞均源自框架中 Python 组件的代码注入缺陷，按照通用缺陷枚举（CWE）系统分类，属于 CWE-94（代码注入）类型。安全研究人员 Yu Rong 和 Hao Fan 发现并报告了这些关键漏洞，随后 NVIDIA 的产品安全事件响应团队（PSIRT）进行了处理。  
  
  
漏洞危害  
  
这两个漏洞的存在，使得攻击者可以通过精心制作的恶意文件，对使用 NVIDIA Megatron LM 框架进行大规模语言模型训练和推理的组织机构造成严重威胁。攻击者利用漏洞成功后，能够实现代码执行、提升权限、信息泄露以及数据篡改等多种恶劣影响，甚至有可能危及整个 AI 基础设施部署。  
  
  
从攻击向量来看，这两个漏洞的模式为 AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H，表明攻击者需要本地系统访问权限，但攻击复杂度低，所需权限也较低，且无需用户交互。攻击者只需向 Megatron LM 系统提供特制的恶意文件，就有可能触发漏洞。  
  
  
影响范围  
  
受影响的产品为 NVIDIA Megatron-LM（涵盖所有平台），其影响范围广泛，涵盖了代码执行、权限提升、信息泄露以及数据篡改等多个方面。攻击者只需具备本地访问权限，且攻击复杂度低、所需权限低，无需用户交互，即可实施攻击，CVSS 3.1 评分为 7.8（高危）。  
  
  
NVIDIA 强烈建议所有 Megatron LM 用户立即从官方 GitHub 仓库升级至 0.12.1 或更高版本。由于漏洞的高危性质，各组织机构应将此次更新作为优先事项。此次安全更新同时解决了 CVE-2025-23264 和 CVE-2025-23265 两个漏洞。运行早期软件分支版本的用户，也应升级至最新分支版本，以确保全面防护。  
  
  
  
NVIDIA Megatron LM 框架出现重大安全漏洞，攻击者可利用漏洞注入恶意代码，获取未授权系统访问权限，用户需立即升级至 0.12.1 或更高版本以应对风险。  
  
  
  
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
  
