#  谷歌单个Chrome漏洞的最高赏金超25万美元   
Sergiu Gatlan  代码卫士   2024-08-29 18:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌将通过其漏洞奖励计划报送的单个 Chrome 漏洞最高赏金提升至原来的2倍，超过25万美元。**  
  
从今天开始，谷歌将根据报告的质量以及研究员查找所报告漏洞的完整影响，对内存损坏漏洞进行分类。通过栈追踪和 PoC 演示Chrome 内存损坏，研究员可获得最高2.5万美元的奖励；而通过可运作利用展示远程代码执行的高质量报告可获得更多。  
  
Chrome 安全工程师 Amy Ressler 表示，“是时候改变 Chrome VRP 奖励和金额了，通过提供优化后的结构和更明确的期待，推动研究员向我们报送并通过高质量的Chrome漏洞报送和更深入的研究，探索这些漏洞的完全影响和可利用性潜力。”  
  
他提到，“如能演示通过单个漏洞利用在非沙箱流程中实现RCE，则研究员可获得最高25万美元的赏金。如果可在未攻陷渲染器的情况下，在非沙箱流程中实现RCE，则可获得包括渲染器RCE赏金在内的更高赏金。”  
  
另外，谷歌还将 MiraclePtr 绕过的赏金从100115美元提升至2倍即250128美元。  
  
谷歌还为其它类型的漏洞设置了奖励，根据报告质量、影响和潜在的用户影响，这些漏洞被分为：  
  
- 低影响：可利用可能性低、利用的前置条件多、攻击者控制低以及用户损害风险/潜力低。  
  
- 中等影响：利用的预置条件中等、攻击者控制程度中等。  
  
- 高影响：可利用路径简单直接、造成的用户损害可演示且重大、具备远程可利用性、利用的预置条件低。  
  
  
  
Ressler 表示，“如报告中包括可应用特征，它们仍然可获得奖励。我们将继续探索更多的类似于之前的‘全链利用奖励’的实验性奖励机会，并改进我们的漏洞奖励计划，更好地服务安全社区。如报告无法演示漏洞对用户造成的安全影响或潜力，或纯粹是理论或推断性问题的报告，则可能无法获得VRP奖励。”  
  
本月早些时候，谷歌还宣布称，因“所报告的可行漏洞数量下降”，将在本月月底即8月31日停止运行Play安全奖励计划 (GPSRP)。7月，谷歌发布了首次在2023年10月披露的kvmCTF 奖励计划，旨在改进KVM 管理程序的安全性，为完整的 VM 逃逸利用提供25万美元的奖励。  
  
自2010年推出漏洞奖励计划 (VRP) 以来，谷歌已为报送超过1.5万个漏洞的安全研究员支付了超过5000万美元的奖励。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[【在野利用】Google Chrome V8 类型混淆漏洞(CVE-2024-5274)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519584&idx=2&sn=dab52360076996946ff35b2afa4a9f72&chksm=ea94bc0adde3351c54d9a36afe23afb6c59f5e81234f6ccbe3b6b07cfc0f71661bf80acac1e4&scene=21#wechat_redirect)  
  
  
[CISA提醒修复严重的Chrome 和 D-Link漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519528&idx=2&sn=39c67314f7459aa04cbef3604ef663a9&chksm=ea94bc42dde3355434c8a075d0b4feaf246269872775783789967ae81284e468716a6872fdaf&scene=21#wechat_redirect)  
  
  
[谷歌修复 Pwn2Own 2024大赛发现的两个 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519170&idx=1&sn=31612ff9461ff59184a818b76f04c198&chksm=ea94baa8dde333be86a1b2054ea40407dfa5a45d469b948ac55085e5f64e7872f7e2007c90ad&scene=21#wechat_redirect)  
  
  
[谷歌修复2024年首个已遭利用的 Chrome 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518705&idx=2&sn=1f6ee90c31f7b70d13390d0a735fe85f&chksm=ea94b89bdde3318da0dc7cd16e5e35198256a22c9c7f0dfa9132e438f6a90fa78fc85e7a63bf&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/google/google-increases-chrome-bug-bounty-rewards-up-to-250-000/  
  
  
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
  
