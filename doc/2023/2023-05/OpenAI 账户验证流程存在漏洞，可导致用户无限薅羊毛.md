#  OpenAI 账户验证流程存在漏洞，可导致用户无限薅羊毛   
Ionut Arghire  代码卫士   2023-05-06 16:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Checkmarx 公司指出，OpenAI 的账户验证流程中存在一个漏洞，可导致任何人使用同一个电话号码注册新账户后，获得无限制的服务额度。**  
  
  
作为人工智能公司，OpenAI 已在几个月来成为媒体焦点，而 ChatGPT 项目的加持使其关注度有增无减。  
  
用户注册新账户时，OpenAI 公司会提供试用期间的免费额度。为防止滥用，OpenAI 执行邮件和电话号码验证机制，如试图使用同一个邮件或电话号码注册多个账户，将不再享有免费额度。这一注册流程始于注册用于接收激活链接的邮件。点击链接要求提供用于通过 SMS 信息接收验证码的电话号码。  
  
研究人员指出，“邮件和电话号码必须是唯一的，否则用户将收到账户已存在的提示且无法获得免费额度。” 研究人员可使用私有域名上的无限别名电子邮件账户以及利用 OpenAI 公司执行的电话号码验证流程中存在的一个漏洞绕过该机制。通过拦截并修改 OpenAI API 请求，研究人员发现攻击者只需提供同一电话号码的变化即可绕过该验证流程，而且仍然拥有为多个账户提供的免费额度。  
  
他们解释称，问题在于，用户提供的电话号码首先会通过一个组件与之前注册的号码进行比对，确保此前未用过。接着，该电话号码被传递给另外一个组件，该组件会在验证之前对其进行清理。因此，攻击者可对同一个号码前置多个0和内联非 ASCII 字节绕过第一次检查，而这些置换不会与原始值相似，同时仍然可通过该号码进行验证，从而可能为无限数量的新账户进行验证。  
  
研究人员解释称，“后一阶段的标准化可引发大量的（如不是无限制的）不同值的集合（如 0123、00123、12\u000a3、001\u000a\u000b2\u000b3等），而这些值会被认为是唯一的标识符，使用时折叠为单个值（123），从而完全绕过初始验证机制。”  
  
在处理值之前可通过运行标准化的方法解决这一问题，从而确保两次检查保持一致。研究员在2022年12月将问题告知 OpenAI 公司，并在2023年3月收到通知称该问题已解决。  
  
****  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[你不问它不说：ChatGPT 创建的大部分代码都不安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516325&idx=1&sn=e4ee4b5aaa31b62978609f490f22e81d&chksm=ea94b1cfdde338d98282904d56362bda945cadbae39cb97602577b5c7349c337d01acdc1c65e&scene=21#wechat_redirect)  
  
  
[研究员成功诱骗 ChatGPT 构建无法被检测到的恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=4&sn=b29b7241f0df2fdbfb34d779834e59f3&chksm=ea94b14adde3385cec864a622b1c368b9584f13da58fd0abc33c7d7a704e43c5749ae1676b23&scene=21#wechat_redirect)  
  
  
[Redis客户端开源库漏洞导致ChatGPT泄漏支付卡信息等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516047&idx=1&sn=6aa14e04c8c7775ff68e6c8cc3b625d1&chksm=ea948ee5dde307f30458a51c238b2dfa50d2fc70f5537f28618295941f6d1236a8d47f705984&scene=21#wechat_redirect)  
  
  
[ChatGPT 出现bug，会话历史标题遭暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516005&idx=1&sn=6079ab0d9b3c2797f1da414b1c2c93e2&chksm=ea948e0fdde30719f22a4c878ae5d3991ea65401a15bb7450a9496c457d77176eddd23cb9520&scene=21#wechat_redirect)  
  
  
[研究员利用ChatGPT制造出多态恶意软件Blackmamba](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515971&idx=2&sn=ff0c41c3c1c97f17f7831960c3252abf&chksm=ea948e29dde3073f190dc2684e4d43d3b9e7955a1598874702f220cb7c08f40ef56e9c7b48e7&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/vulnerability-could-have-been-exploited-for-unlimited-free-credit-on-openai-accounts/  
  
  
题图：Pexels License  
  
  
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
  
