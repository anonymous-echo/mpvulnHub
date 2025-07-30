#  Rapid7 2023年中威胁局势回顾：勒索攻击ROI仍高居不下；0day 漏洞利用规模扩大   
Kevin Townsend  代码卫士   2023-08-29 18:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Rapid7 公司发布的威胁局势回顾报告并未让人感到宽慰。勒索攻击数量仍然居高不下，基础安全措施未被使用，安全成熟度相对较低，勒索犯罪投资回报巨大。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSla5SuZjYomtF2KkjkQZhDbibs6cH8uEmNjEGO8GYAcULuS6MATWhjQvibULw9nX0zr5Fmusv7ExGQ/640?wx_fmt=png "")  
  
  
该报告基于 Rapid7 公司研究人员及其管理服务团队的观察。报告发现，2023年上半年全球的勒索攻击受害者人数超过1500名，包括526名 LockBit 受害者、212名 Alphv/BlackCat 受害者、178名 CI0p 受害者以及133名 BianLian 受害者。这些数据源自泄露网站通信、公开披露以及 Rapid7 公司的事件响应数据。  
  
这些数据应该偏保守，比如并未包含悄悄成功支付赎金的组织机构。另外，下游受害者的数量仍然在增加，例如，报告提到，“归咎于CI0p 组织的事件数量可能（非常）少，因为该组织仍然声称2023年5月发动的 MOVEit Transfer 0day攻击活动还有新增受害者。”  
  
**勒索攻击的成功归因于两大原因：对于犯罪分子而言较高的利润率以及很多潜在目标的不当安全态势。**  
构成后者的元素有三个：首先，近40%的事件是由多因素认证机制缺失或松懈，尽管多年来都在提醒执行这一基础防御措施。第二，很多组织机构的总体安全态势依然低下。Rapid7 公司的顾问为客户执行了多种安全评估，“截至2023年，仅有1家组织机构满足我们根据CIS和NIST基准而提出的安全成熟度最低建议要求。”虽然这些企业的安全性在评估后会得到大幅提升，但这些数据表明，大量组织机构未能满足最低安全标准。第三个因素是对第二个因素的增强，老旧漏洞仍然可使攻击者获得成功。报告指出，“2023年上半年的两大引人注目的例子是Rapid7公司在 SonicWall SMA 100 系列设备中发现的漏洞CVE-2021-20038和在 sudo 命令中的可导致信息泄露和命令执行的漏洞CVE-2017-1000367。”  
  
**这并不意味着2023年上半年未发现新漏洞。**  
报告提到，“超过三分之一的广泛传播的威胁漏洞用于0day 攻击中，而这些漏洞在遭利用的2023年CVE漏洞中仍然普遍存在。我们的团队还发现数个 Adobe ColdFusion CVE-2023-26360的利用实例，这可能说明漏洞的利用广泛程度要高于Adobe 在安全公告中提到的‘非常有限的攻击’。”  
  
**然而，有组织的犯罪（如勒索团伙）并不会因为有能力就去攻击企业，它的驱动力是经济利益。**  
报告说明了网络犯罪的利润究竟有多大。暗网对利用经纪人的需求仍然在，无数网络设备0day利用的售价可高达7.5万美元。报告指出，即使买价是当前金额的十倍，勒索攻击中的一次成功利用就能带来可观的投资回报。  
  
报告提到，“如CI0p这样的威胁行动者十之八九能够轻松负担起易受攻击企业软件的批量 0day 利用成本，这些漏洞可使这些团伙在对高回报目标实施侦查的同时夯实专有能力。这也并非理论用例；多项指标说明CI0p组织在今年的阵亡将士纪念日将MOVEit Transfer 0day (CVE-2023-34362)部署到高度协同的攻击之前，已经对该漏洞进行了近两年的测试。”  
  
这份报告难以让人安心。网络犯罪存在巨大的金融激励，组织机构仍然未能执行基本的安全防御措施（如多因素认证机制和打补丁），加上复杂度不断增强的云、有经验安全劳力的缺失以及受经济不确定性困扰的网络安全投资，网络安全整体局势可能会变得更加糟糕。  
  
当问到 Rapid7 公司漏洞研究主管 Caitlin Condon 从报告中得到的启发时，她指出，“我们管理服务团队所看到的如此多的初始访问向量是由缺乏基本的安全清洁造成的。这并非我们想要看到的数字。当我们了解到组织机构仍然在于如此多的复杂攻击作斗争时，我们不希望看到如此可预防的攻击。但好在，从理论上来讲，执行多因素认证机制等是一种已知的可量化和可定义的行动，如果组织机构想就一定能做到。”可预防攻击仍然在发生，因此基本防御仍然重要。她补充道，“组织机构并非无能为力。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Rapid7 部分源代码遭泄露，成 Codecov 供应链攻击第四个受害者](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247504205&idx=2&sn=c6c6a1e1d7664f2cf0cd512eb2e1ec79&chksm=ea94e027dde36931865cefde36e6a50712463428d81f0754b5a120221989a9c43a90a47545dc&scene=21#wechat_redirect)  
  
  
[Rapid7 的 Nexpose 扫描器 SSH 使用过期的加密算法 (CVE-2017-5243)](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485518&idx=2&sn=7248ed97ffa75cfac505ab353aa9eec5&chksm=ea973924dde0b032bcbcc2c74aaec3c37ee0fbf58095a61ec2f363bfb05841626ece5c4904e6&scene=21#wechat_redirect)  
  
  
[Ivanti 紧急修复 API 认证绕过0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517421&idx=1&sn=31756dd565b1bbd216e954def83c61dc&chksm=ea94b587dde33c91e83a737ae3eb0a14c48a427523b94dba12823b03eac1cecf97a890e21afa&scene=21#wechat_redirect)  
  
  
[Salesforce 邮件服务0day用于钓鱼攻击活动](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517307&idx=1&sn=26cfad6c669ec577ec8907950826b5c8&chksm=ea94b511dde33c077dd3527a4599003fb1642d19fa4d39f96bb7d85c79dc6bf7f0166a73df88&scene=21#wechat_redirect)  
  
  
[台积电称供应商遭勒索攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516908&idx=2&sn=cd41cb805ea798b523f4d6de4308f096&chksm=ea94b386dde33a90ddaf82f19c47db1b4f808a66ffe22513bbef7914ac3cb6b86dca85216925&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/rapid7-says-roi-for-ransomware-remains-high-zero-day-usage-expands/  
  
  
题图：  
Pixabay  
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
  
