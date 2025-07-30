#  DragonForce 勒索团伙瞄准MSP，发动供应链攻击   
Alexander Culafi  代码卫士   2025-05-28 10:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
  
  
**DragonForce 勒索团伙攻击了一家服务管理提供商 (MSP) 的远程监控和管理 (RMM) 工具，发动供应链攻击。**  
  
Sophos 公司发布文章称，从2023年浮出水面并以勒索软件即服务(RaaS) 而为人所知的勒索团伙 DragonForce，组合利用 RMM 工具 SimpleHelp 中的三个漏洞，将勒索软件部署在多个端点，攻击下游客户。  
  
这起MSP供应链攻击只是 DragonForce 团伙最新发动的一起攻击，而它正在迅速成为犯罪分子更为热门的选择之一。  
  
  
**0****1**  
   
**SimpleHelp 的多个漏洞遭利用**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS3XPh6Tkzusx3mSJgo0MKyiat2picnqY5FaSpxbwUx4phGPZZoria7QIEJeEcjUeFlDdiaYtRjn6EzDA/640?wx_fmt=png&from=appmsg "")  
  
  
  
SimpleHelp 是一款用于多种业务场景中的客户支持和远程访问工具；然而，和许多其它的远程访问工具一样，它还是旨在通过漏洞（如本例）或者通过支持欺诈/社工攻击方式获得高权限访问的威胁人员严重的热门目标。  
  
这些漏洞在1月公布，包括多个被统称为路径遍历漏洞的CVE-2024-57727、一个任意文件上传漏洞CVE-2024-57728和一个提权漏洞CVE-2024-57726。  
  
SimpleHelp 的一名发言人表示，这些漏洞影响 SimpleHelp 5.5.6及更早版本，并且“在收到漏洞通知的48小时内，我们调查、开发和验证了每个漏洞的修复方案并发布更新”。  
  
该发言人还表示，“大多客户在新发布之后很短的时间内就按照我们的安全通告进行了更新。就我们所知，在接下来几天内更新至安全发布（或应用了我们为更老旧发布免费准备的补丁）的用户无人受漏洞利用影响。遗憾的是，不久之后以及在一些客户能够更新之前，该漏洞的CVE编号和详情就被公开。我们非常重视安全问题，我们将继续投入更多主动措施来增强自身的安全态势。”  
  
建议客户将SimpleHelp 实例尽快更新至已修复版本。  
  
Sophos 在文章中提到，通过自家的管理检测和响应 (MDR) 产品在一名客户的计算机上检测到“一个 SimpleHelp 安装程序文件的可疑安装”，并提到，“该安装程序通过一个合法的 SimpleHelp RMM 实例推送，由一个MSP为客户进行托管和运营。”  
  
除了恶意像客户推送 SimpleHelp 实例外，攻击者还利用对MSP的访问权限获得对很多客户的访问权限。该MSP的其中一名客户能够通过 MDR 和检测和响应扩展 (XDR) 能力关闭攻击者的访问权限，但很多其它下游客户受该勒索软件和数据盗取影响，从而遭受双重勒索攻击。  
  
  
**0****2**  
   
**DragonForce：“以客户为本”的勒索软件**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS3XPh6Tkzusx3mSJgo0MKyiat2picnqY5FaSpxbwUx4phGPZZoria7QIEJeEcjUeFlDdiaYtRjn6EzDA/640?wx_fmt=png&from=appmsg "")  
  
  
  
Sophos 无法判断这起MSP攻击由 DragonForce 本身还是其附属团伙发动，但无论如何，这起攻击展示了攻击者如何快速在地下生态系统中获得热度。  
  
造成这种情况的部分原因是其“以客户为本”的做法；它利用唯一模型使其分支不但能够完全部署DragonForce 勒索软件，还能够在DragonForce的基础设施和工具基础上使用自身的“品牌”。3月31日，多产的 RaaS 团伙 RansomHub 的泄露网站下线，其中一些成员似乎转向了 DragonForce 的怀抱。而在释放出奇怪的恶意收购信号后，DragonForce 显然涂鸦了 BlackLock 和 Mamona 勒索团伙的泄露网站，时间正好和其在3月19日宣布将成为“卡特尔”重合。DragonForce 团伙还声称发动针对英国零售商 Harrods、Marks & Spencer 和 Co-op 的高级别攻击。  
  
Sophos 威胁应对部门的威胁情报总监 Rafe Pilling 表示，从推广角度来看，DragonForce 是自 LockBit 以来见过的最激进的团伙之一。他表示，“DragonForce 是当前最炙手可热的品牌之一，在地下论坛非常激进地打广告。它们还提出与分支/合作伙伴利润八二分成，以示激励。当前，从勒索软件事件来看，它们并非最活跃的团伙（Akira 团伙占据第一），但几个月后可能会发生变化。”  
  
Rapid7 公司的威胁分析高级总监 Christiaan Beek 认为 DragonForce “是非分支或无组织威胁人员的具有吸引力的枢纽，尤其是在4月份 RansomHub 消失事件之后更是如此。”Beek 表示，迄今为止超过70起公开报道的攻击与该团伙有关。他表示，“DragonForce 似乎并不会基于行业或地理位置而区别对待，它们正在成为新时代的勒索软件即服务的代表：由灵活性、匿名性、自动化和攻击性双重勒索技术而定义。随着对遗留 RaaS 团伙信任的消逝，DragonForce 正在成为新的、很有诱惑力的替代品。”  
  
Coveware 公司的首席执行官 Bill Siegel 表示，DragonForce 也不过是分崩离析、品牌重组和被取代的团伙圈中的一员，它也通过虚张声势以实现营销目的的众多团伙之一。此外，它并不太像运行严密的传统卡特尔组织，而更像是松散的、不断变化的网络。他表示，“我们看到不断出现新名字，更为大胆的权力言论以及各团伙之间更多的合作关系。所有这一切都指向一个竞争性市场：各团伙都在争取注意力、分支和名声。DragonForce 激进的品宣顺应了这一趋势。它更多的是关于脱颖而出和雇佣，而非改进攻击如何完成的方式。它们的崛起至多说明勒索团伙变得越来越去中心化，从事这一行业也变得越来越容易。”  
  
由于DragonForce 团伙的目的通常是盗取凭据和数据，因此 Sophos 建议防御人员为信息盗取活动执行端点监控、部署密码管理器、为IT何服务台执行严格的身份验证协议，以及例行开展桌面演习活动。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
  
开源  
卫士试用地址：  
https://sast.qianxin.com/#/login  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[国际警方联合端掉勒索软件供应链攻击所用的300台服务器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523113&idx=1&sn=5c274c957c0c6bbd1ff9aa8ad0287c81&scene=21#wechat_redirect)  
  
  
[Blue Yonder 勒索攻击破坏百货商店供应链](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521595&idx=2&sn=d623964635e6b305b27e6eece72e58dc&scene=21#wechat_redirect)  
  
  
[研究员因与媒体分享被勒索盗取的数据遭起诉](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520653&idx=1&sn=4ef91f3a0af6eb43edf0132526463da7&scene=21#wechat_redirect)  
  
  
[CISA：严重的 Jenkins 漏洞已被用于勒索攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520541&idx=2&sn=c8001046f4088bb94fd3ffcd7e6926b0&scene=21#wechat_redirect)  
  
  
[再创新高：财富50强公司支付勒索赎金7500万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520345&idx=1&sn=7a9a31f763f81a2f34e0a4467e8c8bb6&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.darkreading.com/application-security/dragonforce-ransomware-msp-supply-chain-attack  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
