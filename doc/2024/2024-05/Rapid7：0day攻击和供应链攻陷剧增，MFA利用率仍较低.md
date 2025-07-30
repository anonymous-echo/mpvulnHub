#  Rapid7：0day攻击和供应链攻陷剧增，MFA利用率仍较低   
Kevin Townsend  代码卫士   2024-05-28 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Rapid7 公司发布报告称，0day 攻击持续升级，供应链大规模攻陷事件也在不断增多；我们当前仍然未能正确使用多因素认证 (MFA) 机制，目前尚未看到改进迹象。**  
  
  
  
Rapid7 公司发布《2024攻击情报报告》指出，0day漏洞的利用持续增多，且常伴有大规模攻陷事件的增多。该公司的漏洞管理总监 Caitlin Condon 指出，“这是我们三年中第二次看到大规模攻陷事件呈现增长态势。”MOVEit（去年5月被利用，6月初被披露）、Barracuda ESG（最初可能在2022年遭利用但2023年爆发）和Ctirix Bleed（2023年8月被利用）即是可立即想到的案例，而且供应链攻击事件多年来一直在增多。  
  
Condon 表示，“我们看到这些事件更多地源自0day漏洞而非nday漏洞。因此2024年初超过一半的新的大规模威胁CVE漏洞是在厂商有机会执行修复方案前就遭利用，而且当然也早于任何人有机会打补丁之前。三年来这个趋势一直如此。”  
  
这一趋势表明，通过不可防御的0day 漏洞造成的供应链攻陷事件在2024年将仍可能继续。我们仅可尝试提升防御能力，因为0day漏洞数量不会减少，供应链不会减少。  
  
要了解为何0day漏洞会增多，应当考虑网络犯罪团伙的专业性不断增强这一点，并将其与合法业务领域进行比对。厂商从漏洞猎人处购买0day漏洞，以便在他们被利用前修复。这也是Bugcrowd 和 HackerOne 等平台获得巨大成功的原因所在。犯罪分子也能这样做。Condo 表示，“我们可以假设犯罪分子黑客找到了类似数量的漏洞。它起作用的原因是犯罪团伙和供应链都能获利。比如你是有几次成功经历的勒索团伙，手上有大量现金可以从暗网购买0day利用。”她提到，有了这种级别的可用资源，“你并不一定总是需要自研0day漏洞，尽管我确信他们很可能也会这样做。”  
  
话说回来，白帽漏洞猎人都知道漏洞奖励计划对于厂商的吸引力在于“购买”并隐藏漏洞。赏金通常是有条件的，那就是漏洞猎人要签署保密协议。报告中提到，“从我们的经验来看，厂商越发倾向于地悄悄修复安全问题，将公告和CVE漏洞描述延迟数天或数周的时间。即便如此，之后更多的厂商似乎会故意混淆漏洞详情，拒绝发布根因和攻击向量信息，这样做是因为它们认为隐晦性会对抗敌对势力并缓解软件生产商的名誉风险。”  
  
政府要求更高的透明度，而一些厂商看似在对着干，攻击者知道的0day和nday漏洞可能要比我们猜测得还要多。Condon 并未提到这种态度背后的原因，但认为可能是因为政府和厂商（尤其是有股东的上市厂商）的动机不同。她表示，“一方认为只要不会进一步攻陷国家安全，就要确保信息传播得足够广；而另一方试图保护自身财产和声誉。这两种动机不一定和是否共享信息有关，也可能是未得到同等共享级别的框架。”  
  
这份报告带来的最大启示是，攻击者变得越来越复杂、武器越来越完备，、速度也变得越来越快。这一趋势并没有改变的迹象。主动修复措施对于应对这一不断增强的威胁至关重要。多年以来我们都被告诫要假设已发生攻陷并做好响应，一直以来都将防御措施集中在网络内部而损害了边缘设备。而攻击者了解这一点，并在过去几年来增加了对防御不是很好的边缘设备的攻击，他们的目的是借此跳转到常态网络。报告提到，“源自网络边缘设备利用的大规模攻陷事件自2023年开始几乎翻了一番，2023年36%的被利用漏洞发生在网络边界技术中。”检测和响应已不够，预防尤其是边缘设备的预防十分重要。  
  
不过，如果说这份报告只给出一个主要防御观点，那么它就是“在Rapid7 公司2023年调查的事件中，超过40%的事件是因为MFA缺失或执行不一致导致的，尤其是在VPN、VDI和SaaS 产品中的情况更是如此。”  
  
Condon表示，“我们不需要知道细节。这些组织机构真的没有MFA吗？他们只是未正确配置吗？还是并没有执行？但是，是的，它确实拖慢了很多攻击并可以阻止一些攻击。”  
  
MFA（整体的分层安全性）好比为长久的通过环境设计阻止犯罪(CPTED) 的物理策略概念：你让目标建筑尽可能变得没有吸引力。随机的抢劫者将转向不太难的其它目标。在这个类比中，MFA加固了前门——可能和第二个（生物特征）入门设备有关，警报显示越权的不速之客试图进入。MFA虽然无法阻止配有推土机的意志强大的国家攻击者，但却可以震慑数量众多且不太复杂的犯罪分子。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌紧急修复周内第3个已遭利用的0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519506&idx=1&sn=6a998af125698c3afd195f3d1eb96981&chksm=ea94bc78dde3356e58d441d5787adcdb360f70675c569aa3b7e5d7d549868bea76393657c2bd&scene=21#wechat_redirect)  
  
  
[国家黑客组织利用思科两个0day攻击政府网络](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519358&idx=1&sn=080e82a553f5a1d52ba96fc6f20d14c3&chksm=ea94bd14dde33402ba398352628a6ab2995cc8e1c950313b8a1b9fb5752d5c3d7a2f00098df9&scene=21#wechat_redirect)  
  
  
[RSAC 2024观察：软件供应链安全进入AI+时代](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519497&idx=1&sn=3f531af375c16bd26e01ca94f96d2f6b&chksm=ea94bc63dde33575a6c7f4e47536c932046c465934273303f37535c57d30f3fe32e5335b2de5&scene=21#wechat_redirect)  
  
  
[JAVS庭审录制软件被植入后门 用于发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519595&idx=1&sn=5f6ab2056a927eead9909040d3beab23&chksm=ea94bc01dde335176b3d09e077bdb4f6b7edf6f1183927c5ca8c5ade7b6deb17e0e2af72503d&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/zero-day-attacks-and-supply-chain-compromises-surge-mfa-remains-underutilized-rapid7-report/  
  
  
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
  
