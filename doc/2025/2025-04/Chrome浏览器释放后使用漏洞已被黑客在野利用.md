#  Chrome浏览器"释放后使用"漏洞已被黑客在野利用   
邑安科技  邑安全   2025-04-27 03:29  
  
更多全球网络安全资讯尽在邑安全  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v4TWNX2h42Wqr4VEqehAytcP1HZ9mSony57lRO99X5bzr9KBMC8Ogxb9sj5rjiaFiaklx3y65O747A/640?wx_fmt=png&from=appmsg "")  
  
Google Chrome 浏览器面临一系列备受瞩目的安全事件，涉及释放后使用 （UAF） 漏洞，其中有几起漏洞已被广泛利用。  
  
这些缺陷植根于不当的内存管理，已成为攻击者寻求绕过浏览器沙盒并在受害者计算机上执行任意代码的持续威胁媒介。  
  
当程序在引用的内存被释放后继续使用指针时，就会发生 UAF 漏洞。  
  
这可能允许攻击者纵驻留在该内存位置的内容，从而可能导致数据泄漏、代码执行或拒绝服务。  
  
在 Chrome 中，UAF 历来是严重安全漏洞的主要来源，尤其是在浏览器进程中，该进程可以直接访问敏感的用户数据和系统资源。  
  
Chrome UAF 漏洞  
  
CVE-2024-4671 漏洞： 在 Chrome 的 Visuals 组件中发现，负责呈现页面内容。攻击者可以通过诱使用户访问恶意网页来利用此漏洞，从而可能导致任意代码执行。  
  
Google 的回应是发布紧急补丁并隐瞒技术细节，以防止进一步利用。  
  
CVE-2025-2476 漏洞：Chrome 的 Lens 组件中的关键 UAF，影响除 iOS 之外的所有平台。  
  
此漏洞允许远程攻击者通过构建的 HTML 利用堆损坏，绕过 Chrome 的防御并可能接管浏览器会话。  
  
CVE-2025-2783 漏洞：Windows 上的 Mojo IPC 库中存在一个严重性较高的错误，使攻击者能够绕过 Chrome 的沙盒保护。  
  
此缺陷与有针对性的间谍活动有关。  
  
典型的漏洞利用技术涉及堆喷洒，攻击者在触发 UAF 之前用受控数据填充内存，旨在覆盖虚拟函数表 （vTables） 并劫持程序控制流。  
  
根据 SSD Secure Disclosure 技术团队的说法，例如，可以通过纵异步回调并在 Chrome 的密码管理器中执行任务之前销毁对象来触发 UAF。  
  
概念验证代码演示了攻击者如何创建并快速删除浏览器窗口以诱发此类情况：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v4TWNX2h42Wqr4VEqehAytxBcvjQq6sqB7d1wPnYnAia2R4KpXwVLBJFicAkj1jtp1zC8wchMtmudw/640?wx_fmt=png&from=appmsg "")  
  
MiraclePtr 和 BackupRefPtr  
  
为了应对源源不断的 UAF 漏洞，Chrome 部署了 MiraclePtr，这是一种类似智能指针的机制，旨在使 UAF 不可被利用。  
  
这种保护的核心是 BackupRefPtr （BRP） 技术，该技术利用 Chrome 的自定义堆分配器 PartitionAlloc。  
  
每个内存分配都伴随着一个隐藏的引用计数器：  
  
释放对象后，如果引用仍然存在，则会将其移动到隔离区域，而不是立即解除分配。  
  
内存填充有特定的位模式（例如 0xcc），以防止攻击者成功回收和利用该区域。  
  
只有当引用计数降至零时，才会真正释放内存，确保没有悬空指针残留。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8v4TWNX2h42Wqr4VEqehAytlSSK1nOza3LaCO3ibyYRLJnAJKqz5OMkK8f8D5iarbfFHYsoica36LSgA/640?wx_fmt=png&from=appmsg "")  
  
虽然 MiraclePtr 显着提高了攻击者的门槛，但并非所有 Chrome 组件都受到完全保护。强烈建议用户：  
  
立即将 Chrome 更新到最新版本，因为会发布新的补丁来解决这些漏洞。访问不受信任的网站时要小心，在应用更新之前避免与可疑的浏览器功能交互。  
  
组织应监控其环境是否存在过时的 Chrome 版本，并及时部署缓解措施。随着 Chrome 不断强化其内存管理，UAF 漏洞仍然是防御者和攻击者关注的重点。  
  
原文来自: cybersecuritynews.com  
  
原文链接:   
https://cybersecuritynews.com/chrome-uaf-vulnerabilities-exploited/  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
