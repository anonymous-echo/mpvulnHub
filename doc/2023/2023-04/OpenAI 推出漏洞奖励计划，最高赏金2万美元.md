#  OpenAI 推出漏洞奖励计划，最高赏金2万美元   
Sergiu Gatlan  代码卫士   2023-04-12 17:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**AI 研究公司 OpenAI 推出新的漏洞奖励计划，允许已注册安全研究员在其产品线中发现漏洞，并通过 Bugcrowd 众包安全平台报告且获得奖励。**  
  
  
  
OpenAI 公司指出，具体奖励基于所报告问题的严重性和影响程度，奖金从200美元到2万美元不等。该公司指出，“OpenAI 漏洞奖励计划是为了认可并奖励那些保护产品和公司安全的安全研究人员的有价值的洞察力。我们邀请您报告从我们系统中所发现的漏洞、bug 或安全缺陷。通过共享您的研究成果，您为所有人获得更安全的技术起到了关键作用。”  
  
然而，虽然 OpenAI API 及其 ChatGPT 人工智能聊天机器人也涵盖在内，但OpenAI 公司要求研究人员通过另外的一份表单报告模型问题，除非这些问题造成安全影响。该公司指出，“模型安全问题不适用于漏洞奖励计划，因为它们并非单独的、独立的、可被直接修复的 bug。解决这些问题要求开展大量研究以及更加宽泛的方式。为确保这些问题得到正确处理，请填写合适的表单进行报告，而非通过漏洞奖励计划进行提交。在正确的地方报告可使我们的研究员通过这些报告改进模型。” 其它不涵盖的范围包括ChatGPT 用户用来诱骗 ChatGPT 聊天机器人忽略OpenAI 工程师实现的安全防护措施的越狱和安全绕过。  
  
上个月，OpenAI 披露了 ChatGPT 支付卡数据泄露事件，并归咎于 Redis 客户端开源库中的一个漏洞。该漏洞导致 ChatGPT Plus 订阅用户能够在订阅页面中看到其他用户的邮件地址，随着用户报告的增多，OpenAPI 下线 ChatGPT 进行调查。  
  
几天后，OpenAI解释称，该漏洞导致 ChatGPT 服务保护了大约1.2%的 Plus 服务订阅用户的聊天查询和个人信息。被暴露的信息包括订阅用户的姓名、邮件地址、支付地址和部分信用卡信息。OpenAI 公司表示，“该漏洞位于 Redis 客户端开源库 redis-py 中。我们发现该漏洞后，与 Redis 维护人员一起推出补丁，修复该问题。”  
  
虽然 OpenAI 公司并未将这次推出的漏洞奖励计划与该事件相关联，但如果该公司已经设立漏洞奖励计划并允许研究人员对产品中的缺陷进行测试的话，漏洞可能会更早地发现，而数据泄露事件本可避免。  
  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Redis客户端开源库漏洞导致ChatGPT泄漏支付卡信息等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516047&idx=1&sn=6aa14e04c8c7775ff68e6c8cc3b625d1&chksm=ea948ee5dde307f30458a51c238b2dfa50d2fc70f5537f28618295941f6d1236a8d47f705984&scene=21#wechat_redirect)  
  
  
[ChatGPT 出现bug，会话历史标题遭暴露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516005&idx=1&sn=6079ab0d9b3c2797f1da414b1c2c93e2&chksm=ea948e0fdde30719f22a4c878ae5d3991ea65401a15bb7450a9496c457d77176eddd23cb9520&scene=21#wechat_redirect)  
  
  
[3·15特辑 | 少侠，可曾听说ChatGPT也有“食品安全问题”？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515947&idx=1&sn=b56dd235a7b662303755b8335f83ec7b&chksm=ea948e41dde3075753ae1779a5395a0f4a4e4550aa2a86eb793e75e897e78c286efccd83e9cd&scene=21#wechat_redirect)  
  
  
[【DEF CON会议】OpenAI Gym---能创建“不可见”恶意软件的机器学习系统](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485492&idx=7&sn=638da4379be0ab30a999d2c0f072fe10&chksm=ea97395edde0b0480f6a54d628485d7a17f49be3f21275c24e00bbe4ed39f046e66b4e8cff74&scene=21#wechat_redirect)  
  
  
[研究员成功诱骗 ChatGPT 构建无法被检测到的恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=4&sn=b29b7241f0df2fdbfb34d779834e59f3&chksm=ea94b14adde3385cec864a622b1c368b9584f13da58fd0abc33c7d7a704e43c5749ae1676b23&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/openai-launches-bug-bounty-program-with-rewards-up-to-20k/  
  
  
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
  
