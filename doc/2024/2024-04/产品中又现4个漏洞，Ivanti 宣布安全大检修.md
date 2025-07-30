#  产品中又现4个漏洞，Ivanti 宣布安全大检修   
Jai Vijayan  代码卫士   2024-04-08 17:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Ivanti 公司的首席执行官 Jeff Abbott 上周表示，公司将改变安全实践，即使目前在本已漏洞密布的 Ivanti Connect Secure 和 Policy Secure 远程访问产品中又发现其它一些漏洞。**  
  
  
  
Abbott 在向客户发送的公开信件中表示，由于继1月份以来连续披露漏洞，Ivanti 将在未来几个月中做出的改革安全运营模式的变化。该公司承诺的修复方案包括对 Ivanti 工程、安全和漏洞管理流程的完全改造以及关于产品开发的新的设计安全计划。  
  
  
**全面检修**  
  
  
Abbott 在声明中提到，“我们严格审查所有流程的每个阶段和每款产品，确保客户能够获得最高级别的防护。我们已经开始应用从近期事件中吸取的经验教训，立即改进自身的工程和安全实践。”  
  
其中一些特定步骤包括在软件开发生命周期中的每个阶段嵌入安全性，在产品中集成新的隔离和反利用特性，将软件漏洞的影响将至最低。Ivanti 公司还将改进内部漏洞发现和管理流程并提高对第三方漏洞猎人的激励措施。  
  
另外，公司将向客户投入更多资源，发现漏洞信息和相关文档，并致力于与客户更多的变革和信息共享。鉴于该公司近期的安全表现，这些承诺对于阻断不断增长的客户担忧究竟起到什么作用还有待商榷。实际上，Abbot 的承诺就发生在 Ivanti 披露 Connect Secure 和 Policy Secure 网关技术中四个新漏洞及其补丁的一天之后。  
  
而在两周前，Ivanti 适用于ITSM 产品的 Standalone Sentry 和 Neuron 中就被指存在两个漏洞。从1月份开始，Ivanti 公司截止目前已披露11个漏洞（含这4个新漏洞）。其中很多漏洞是位于远程访问产品中的严重漏洞，至少两个是 0day 漏洞，而这些漏洞遭到APT组织在内的攻击者利用。其中一些漏洞的影响范围之广导致CISA在1月份要求联邦机构下线 Ivanti 系统，且在漏洞修复前不能重新连接这些设备。  
  
安全研究员兼IANS 安全成员 Jake Williams 表示，这些漏洞披露引发客户提起更严重的问题。他表示，“从我所参与的交谈来看，尤其是和财富500强客户的交谈，我认为做得太少也太晚了。公开发布这些承诺的时机应该是在一个多月前。”他表示，Ivanti VPN 设备中的这些问题导致首席信息安全官质疑 Ivanti 公司很多其它产品的安全性。  
  
  
**四个新漏洞**  
  
  
Ivanti 公司在本周披露的四个新漏洞包括位于 Connect Secure 和 Policy Secure 的IPSec 组件中的两个堆溢出漏洞，它们都被认为是高危漏洞。其中一个漏洞CVE-2024-21894可导致未认证攻击者在受影响系统上执行任意代码。另外一个漏洞CVE-2024-22053可导致未认证远程攻击者在某些条件下从系统内存中读取内容。Ivanti指出这两个漏洞都可导致攻击者发送恶意构造的请求，触发拒绝服务条件。  
  
另外两个漏洞CVE-2024-22052和CVE-2024-22023均为中危漏洞，可被攻击者用于引发拒绝服务条件。Ivanti 公司表示，截止到4月2日，还未发现漏洞遭利用的迹象。  
  
如此稳定的漏洞披露已经引发全球4万多家客户对于 Ivanti 公司产品风险的关注，其中一些客户在论坛上表达了这种受挫心情。就在两年前，Ivanti 公司发布新闻稿称在财富100强公司中，其中96家公司是其客户。在最新发布的文章中，这一数字掉到了85家。虽然这种变化可能和安全以外的因素行管，但一些竞争对手已经嗅到了商机。例如，思科已经开始提供为期90天的免费试用服务，试图将Ivanti VPN 客户迁移至思科 Secure Access 平台，从而“缓解”来自Ivanti 产品的“风险”。  
  
  
**收购相关的问题？**  
  
  
Omdia 公司的分析师 Eric Parizo 表示，Ivanti 公司面临的至少一些挑战和该公司过去收购的很多产品组合有关。他提到，“原始产品由不同企业在不断时期出于不同目的使用不同方法开发而成。这意味着软件质量，尤其是与软件安全相关的质量可能波动较大。”  
  
Parizo 表示，Ivanti 公司目前正在努力改进安全流程和程序，这是向正确方向迈出的一步。他标识号，“我希望看到该厂商能够为客户赔偿因这些漏洞造成的直接损失，因为这样做会恢复未来采购的信心。对 Ivanti 有利的方面可能在于客户习惯了这种事件，因为近年来网络安全厂商遭遇了无数次类似事件，客户更可能会谅解和忘记。”****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Ivanti 修复由北约报送的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519117&idx=1&sn=cde689326429491acd44848ceeacab57&chksm=ea94bae7dde333f1f0011d550d4f6a0c206cfdb62dda27f77ba6e432c6883a80c8ff30be2a51&scene=21#wechat_redirect)  
  
  
[Ivanti 披露两个新0day，其中一个已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518800&idx=2&sn=81cdaabe53353075dd5badd918a3e0cd&chksm=ea94bb3adde3322ca6046c2aa9cb37dedf686efcdd6be90bd63248f23ad20dcc4015a3007149&scene=21#wechat_redirect)  
  
  
[第三个 Ivanti 漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518721&idx=2&sn=0fecc3da2d3d00906eb9f4f79279a328&chksm=ea94bb6bdde3327dc06586f79bb98cb915165183da490c1b063cf84fb4571cce6ae8e8396b99&scene=21#wechat_redirect)  
  
  
[严重的Ivanti EPM 漏洞可导致黑客劫持已注册设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518594&idx=1&sn=42344cd84f041e0bd0049ef5c7bbdf84&chksm=ea94b8e8dde331fe2a1df497c6a9068b0b510c2924d9229f7c28997fee0d5b1c8a1d81cd78aa&scene=21#wechat_redirect)  
  
  
[Ivanti 修复 Avalanche 中的13个严重 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=2&sn=11cb31fa8a53f1561ec28a3e9a63da6e&chksm=ea94b991dde33087c9606baa5ebb64e71528283f676f497d3123ca31f84cc1ce1f3e971e8184&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/remote-workforce/ivanti-ceo-commits-to-security-overhaul-day-after-vendor-discloses-4-more-vulns  
  
  
题图：  
Pexels  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
