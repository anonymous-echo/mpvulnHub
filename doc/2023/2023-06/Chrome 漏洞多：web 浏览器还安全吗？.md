#  Chrome 漏洞多：web 浏览器还安全吗？   
Kevin Townsend  代码卫士   2023-06-27 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**和所有大型应用程序一样，谷歌 Chrome 也饱受漏洞之苦。2022年期间，SecurityWeek 媒体报道发现456个漏洞（每月平均38个漏洞），其中9个0day 漏洞。需要修复的漏洞如此之多，一个简单的问题是：Chrome 浏览器还安全吗？**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMT4iaxR3y6HH5g9QdEWliaAt1Z9OalNkldzEeibolnh1PruswoeLrUBJoJrmFdRfZqEkZT7X9ugeXU3A/640?wx_fmt=png "")  
  
  
2023年，高频率的漏洞披露和补丁还在继续。Chrome 109 在1月份修复了23个漏洞。Chrome 110 在2月份修复了15个漏洞；版本111在3月份修复了48个漏洞；版本112在4月份修复了16个漏洞。4月份还修复了2023年以来的第二个0day。版本113在5月份修复了15个漏洞，后来又修复了12个。6月份最开始Chrome 114修复了2023年以来的第三个0day，后续又发布了5个补丁。  
  
漏洞修复清单很长，几乎变成了单调的重复，但毫无疑问，这一清单将继续如此。然而，它所引发的问题让人思考：为什么会有这么多漏洞？Chrome 浏览器还安全吗？谷歌是否会加强安全措施？用户是否可提高自身安全性？以色列公司 Perception Point 的首席技术官 Tal Zamir 就这些话题发表了自己的看法。  
  
漏洞数量多的主要原因从根本上说是统计问题。它是代码库规模、目标的吸引程度和用户量的组合结果。Zamir 提到，“多年来，Chrome 已成为庞大的代码库，规模基本相当于 Windows 这样的操作系统，因为它包含很多特性。”  
  
他补充道，“它看似简单，人们以为只是一个浏览器应用。但实际上，它是一头巨兽。它是人们一天多数时候都会使用的应用程序，在企业和客户领域均如此。这是我们多数网络活动所用的应用程序。”  
  
代码库越大，漏洞数量就越多。这是计算的现实。一款应用程序使用的次数越多，那么攻击者试图攻击的尝试就越多。攻击者包括犯罪分子、国家黑客组织等，而且无可避免会遭攻击。值得注意的是，Statcounter 在2023年5月发布报告指出，Chrome 在全球浏览器市场的占比达到62.87%。Safari 以20.7%排名第二，而Edge 仅以5.32%位列第三。  
  
我们无法期待谷歌提供更多安全措施，保护代码安全。这也是一个不可避免的商业社会特性。为此，谷歌不得不减少推出新特性的数量和速度，而这与确保以及可能提升市场份额是相悖的。微软一直处于追赶浏览器的状态，不过通过将AI集成到产品中，它现在火力全开（即利润最大）。  
  
Zamir 认为，“微软对谷歌发起真正的战争，不仅在企业领域如此，对于动心谷歌服务包的客户而言也是如此。我预计谷歌更难应战并在浏览器领域保持领头羊位置。在这次对战中，它将增加新特性且尝试以更快的速度创新。这样做的时候，通常会把安全放在次要位置。速度是需求——需要将闪亮的新东西放在用户面前，而安全可能滞后。这并不意味着谷歌将忽略安全，它肯定在 Chrome 安全性方面进行投资，但我认为相对于新特性而言，安全是第二位的。”  
  
谷歌不应受到批评的地方是其对 Chrome 安全的响应式方法。其策略是寻找（通过自身的研究团队和漏洞奖励计划），之后在漏洞遭滥用之前修复和打补丁。  
  
这是一种响应式方法，而非主动式方法。虽然谷歌自身受商业现实所迫不得不对安全采取响应式方法，而多数企业均如此，但用户可采取更加主动的方式。这不可避免地涉及增加专门的产品来保护应用程序及其使用的安全性。  
  
这就引发另一个问题：如果小型安全企业能够保护 Chrome，那么为何谷歌（全球最大的开发者之一）不在 Chrome 内部开发类似防护措施呢？“谷歌当然能够做到，”Zamir认为，“如果它愿意投入数年的工程。”  
  
从技术上来讲，这样做是可能的，但从经济角度来看是不可行的。回到“闪亮的新东西”形象中。对于 Chrome 而言，闪亮的新东西就是吸引用户的额外特性，因此会被推到优先位置。但对于第三方安全厂商而言，安全才是闪亮的新东西。  
  
这就是现代网络安全的现实。我们无法假设任何一款应用程序是安全的或者该应用程序的厂商会确保你是安全的。所有用户必须为所使用产品的安全负责。谷歌 Chrome 是本次讨论所选取的不幸案例，但这些原则适用于几乎所有的商业应用程序。****  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Google Chrome V8 类型混淆漏洞 (CVE-2023-3079) 安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516688&idx=1&sn=6978d8fa7462da7ef65701cf3c8b0bb0&chksm=ea94b37adde33a6cdab8577cd9bafe14b03d644313a391dec990133584467d5c4569de739db7&scene=21#wechat_redirect)  
  
  
[谷歌为 Chrome 沙箱逃逸利用链提供三倍赏金](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516649&idx=1&sn=4e785a24db31c0a5ba6444f993a7c15e&chksm=ea94b083dde339956da54b6ff9b4036c037a976bad07e12c44d2db445eef51db0ed4c00ef820&scene=21#wechat_redirect)  
  
  
[Chrome 114 发布18个漏洞补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516632&idx=2&sn=6facb00a2129b1781ccdfcfda5ba6032&chksm=ea94b0b2dde339a4b08ad29601e05b57e19dce03c622d127ff45336a2fbabf8f8c427990f5be&scene=21#wechat_redirect)  
  
  
[谷歌修复今年的第二个已遭利用 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516282&idx=1&sn=52eb5c1094115b783391abfa147ff39a&chksm=ea94b110dde3380674f5e90137e75fac973293e981e63b279fe6617e8a82bd25e2a2d066eccf&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复2023年第一个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516252&idx=1&sn=8371d9c05433cba2f5df47f101e8ad05&chksm=ea94b136dde33820c0033b8827312e06fe8bf7770075580020919000bdd6049133fc97d2a49e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/chrome-and-its-vulnerabilities-is-the-web-browser-safe-to-use/  
  
  
题图：Pixabay License  
  
  
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
  
