#  Redis客户端开源库漏洞导致ChatGPT泄漏支付卡信息等   
Lawrence Abrams  代码卫士   2023-03-27 17:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTshNd2iamlSye8z4iap7MWprs1sgKI0vGPicYMPaHEHNotv4QH7fSH3jD4VPruch4nuepJ4TrLWevRw/640?wx_fmt=gif "")  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTshNd2iamlSye8z4iap7MWprRGTtibADnCBL9xibUZjMxEIe3g6XH6ye6M9CL7cNlHuNZDLkB3mXP38g/640?wx_fmt=gif "")  
  
**OpenAI 公司指出，Redis 客户端开源库漏洞是上周一ChatGPT服务中断以及数据泄露的元凶。该攻击使用户能够看到其他人的个人信息和聊天查询。**  
  
ChatGPT 在侧边栏展示用户所提的历史查询，可使用户点击这些查询使GPT重新生成响应。上周一，很多ChatGPT 用户称可以在自己的历史中看到其他人的聊天查询。PC Magazine 媒体率先报道了此情况，称多名ChatGPT Plus 服务的订阅用户也可在订阅页面看到其他用户的邮件地址。之后，OpenAI 将ChatGPT 下线调查此事，但该公司并未说明服务中断详情。  
  
  
**开源库漏洞导致数据泄露**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTshNd2iamlSye8z4iap7MWprs1sgKI0vGPicYMPaHEHNotv4QH7fSH3jD4VPruch4nuepJ4TrLWevRw/640?wx_fmt=gif "")  
  
  
****  
OpenAI 发布报告解释称，Redis 客户端的开源库中存在一个漏洞，导致ChatGPT 服务暴露了其他用户的聊天查询以及1.2%的ChatGPT Plus订阅用户的个人信息。  
  
OpenAI 指出，“该漏洞位于Redis开源库 redis-py 中。我们发现该漏洞后与Redis 维护人员联系，并获得相关补丁解决了该漏洞。”  
  
被暴露的信息保护订阅用户的姓名、邮件地址、支付地址和信用卡号的最后四个数字以及失效日期。报告中提到，“深入调查后，我们还发现该漏洞也可能导致在9小时时间窗口内的1.2%的ChatGPT Plus订阅用户的支付相关信息遭非故意泄露。周一下线ChatGPT的几小时前，一些用户很可能看到了其他活跃用户的姓氏和名字、邮件地址、支付卡地址、信用卡号的最后四位数字和信用卡失效日期。完整的信用卡卡号并未遭暴露。”  
  
OpenAI 表示，数据遭暴露的人员数量可能非常少，因为数据泄露发生的特定要求是：  
  
- 用户须在太平洋时间3月20日上午1点至10点之间，打开订阅确认邮件。  
  
- 用户须在在太平洋时间3月20日上午1点至10点之间，ChatGPT中点击“我的账户“，之后点击”管理我的订阅“。  
  
  
  
OpenAI 公司表示，他们正在联系所有支付信息遭暴露的ChatGPT 用户。该公司的首席执行官 Sam Altman 在周三晚推特上就此事致歉。  
  
他写道，“因为开源库中的一个漏洞，我们的ChatGPT 遭受重大问题，目前修复方案已发布，我们刚验证结束。一少部分用户能够看到其他用户会话历史的标题。我们对此深感抱歉。”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[ChatGPT 出现bug，会话历史标题遭暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516005&idx=1&sn=6079ab0d9b3c2797f1da414b1c2c93e2&chksm=ea948e0fdde30719f22a4c878ae5d3991ea65401a15bb7450a9496c457d77176eddd23cb9520&scene=21#wechat_redirect)  
  
  
[研究员利用ChatGPT制造出多态恶意软件Blackmamba](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515971&idx=2&sn=ff0c41c3c1c97f17f7831960c3252abf&chksm=ea948e29dde3073f190dc2684e4d43d3b9e7955a1598874702f220cb7c08f40ef56e9c7b48e7&scene=21#wechat_redirect)  
  
  
[3·15特辑 | 少侠，可曾听说ChatGPT也有“食品安全问题”？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515947&idx=1&sn=b56dd235a7b662303755b8335f83ec7b&chksm=ea948e41dde3075753ae1779a5395a0f4a4e4550aa2a86eb793e75e897e78c286efccd83e9cd&scene=21#wechat_redirect)  
  
  
[攻击者已利用ChatGPT编写恶意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515233&idx=3&sn=acc0f7a96702e65796637a360acf5510&chksm=ea948d0bdde3041dc094027cc96639bf548ab737e3da4cbb80f6cb46f6c3bad46bb7c78a2dc5&scene=21#wechat_redirect)  
  
  
[学生利用“提示符注入”方法，攻破ChatGPT版必应搜索](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515534&idx=2&sn=e816e0c34f1deae1b5278e39c974e4ff&chksm=ea948ce4dde305f27ad16099811f247a67e25343957dfde04cb07203fa48927237f458d883d4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/openai-chatgpt-payment-data-leak-caused-by-open-source-bug/  
  
  
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
  
