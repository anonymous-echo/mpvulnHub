#  Microsoft Outlook 曝高危漏洞，仅需低权限就能实施攻击  
看雪学苑  看雪学苑   2025-06-11 09:59  
  
2025年6月10日，Microsoft Outlook 被曝出 CVE-2025-47176 高危漏洞，攻击者可借此远程执行任意代码。  
  
  
此漏洞  
编号为 CVE-2025-47176，被评定为 “重要” 级别，CVSS 评分高达 7.8 分，属于高风险漏洞范畴。该漏洞使得攻击者即使自身身处远程，也具备了在用户电脑上执行任意代码的危险能力，且关键点在于，仅需低权限就能实施攻击。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8E9iasJ0EU96jUTAwwm9KUwr9MrPTI6JfD9MXYxCusMEia6P2n0CUG44VIU41AeWzzic2YDp8l7ibibkgQ/640?wx_fmt=png&from=appmsg "")  
  
  
从技术层面剖析，这一漏洞的根源在于 Microsoft Outlook 存在着路径遍历问题，涉及 “…/…//” 这样的特殊序列。研究人员通过深入研究发现，攻击者可以巧妙地利用这些序列，玩弄文件路径于股掌之间。如此一来，攻击者就能在目标系统上实现本地代码执行。虽说从分类上看，这属于本地攻击向量，但微软官方严肃指出，这实则构成了远程代码执行（RCE）漏洞，因为 “远程” 关键词指向的是攻击者的所在位置，而非执行手段。  
  
  
深入探究其影响范围，可谓覆盖了信息安全的三大核心支柱 —— 保密性、完整性和可用性，且这三项在 CVSS 评估里均被判定为 “高” 级别。试想，若攻击者成功得逞，他们将如入无人之境般获取电脑内的各类敏感数据，重要文件、隐私信息等都可能被一网打尽，这是对保密性的严重破坏；系统配置也会被其随意篡改，完整性荡然无存；更甚者，攻击者还极有可能让电脑陷入瘫痪，无法正常使用，直接损害了可用性。  
  
  
回溯这一漏洞的发现之旅，是 Morphisec 团队里的 Shmuel Uzan、Michael Gorelik、Arnold Osipov 这几位安全专家，在日常严谨的网络安全研究中捕获了这个隐患。他们秉持着负责任的态度，采取了协调披露的方式，及时将漏洞信息告知了微软，为后续的漏洞修复争取了宝贵时间。  
  
  
说到攻击方式，虽然官方将攻击向量定为本地（AV:L），但现实场景里，攻击者完全能搭建起远程代码执行的桥梁。不过，有一点值得稍微安心，微软已明确说明，该漏洞的攻击途径不包括预览窗格，这一定程度上限制了一些惯常依赖被动内容渲染的攻击场景。  
  
  
在威胁情报层面，目前好消息是，暂未有迹象表明此漏洞在官方公告前已被公开披露，也未曾监测到在真实网络环境中被大规模利用，但微软对其可被利用性评估为 “不太可能”，谁也无法保证不法分子不会后续开发出针对性的攻击手段。  
  
  
  
资讯来  
源  
：  
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
  
