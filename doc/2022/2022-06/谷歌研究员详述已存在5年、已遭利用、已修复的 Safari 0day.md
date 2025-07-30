#  谷歌研究员详述已存在5年、已遭利用、已修复的 Safari 0day   
Ravie Lakshmanan  代码卫士   2022-06-21 17:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMThIz9axluNe2c2NRzcN1SNcQcEB7Fk3ffsSY8tTpNG8ZFubaaAuMrX4EhhyjmdibaxxWLFfQFXnOg/640?wx_fmt=png "")  
  
谷歌 Project Zero 团队发布报告指出，苹果 Safari 中存在一个严重的释放后使用 (UAF) 漏洞 (CVE-2022-22620) ，在今年年初遭在野利用，最初在2013年修复之后在2016年12月重新引入。  
  
  
  
CVE-2022-22620的CVSS 评分为8.8，是位于 WebKit 组件中的一个释放后使用漏洞，可被特殊构造的 web 内容用于执行任意代码。  
  
2022年2月初，苹果修复了位于 Safari、iOS、iPadOS 和 macOS 中的这个漏洞，并承认“可能已遭在野利用”。  
  
谷歌 Project Zero 团队的研究员 Maddie Stone 指出，“在这种情况下，该变体在2013年最初被报告时完全被修复。然而，在三年后的大规模代码重构过程该变体再次被引入。之后，该漏洞一直存在了5年，直到2022年1月以在野遭利用0day的状态修复。”  
  
虽然2013年和2022年的History API 中的漏洞本质上是一样的，但触发该漏洞的路径不同。多年后执行的代码更改使该漏洞像僵尸一样复活了。  
  
Stone 指出，该事件并不只存在 Safari 中，之后他花时间审计了代码和补丁，避免复制修复方案并了解了这些代码更改带来的安全影响。他提到，“2016年10月和2016年12月的提交都非常庞大。10月份的提交修改了40个文件，其中有900处增加和1225处删除操作。12月份的提交更改了95份文件，其中有1336处增加和1325处删除操作。似乎任何开发人员或审计人员都难以详细了解这些提交中每个更改带来的安全影响，尤其是当这些提交和整个生命周期的语义相关时。”  
  
具体技术分析可见：  
  
https://googleprojectzero.blogspot.com/2022/06/an-autopsy-on-zombie-in-wild-0-day.html  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[0day影响 Chrome和 Safari，谷歌不修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501665&idx=2&sn=a09093a7dcd1fc94b872c4ca7b46bfb1&chksm=ea94f60bdde37f1d02f2b144aebb3a4fcd8325b46a136a7189d1789252f1089384dcfa9c969c&scene=21#wechat_redirect)  
  
  
[研究员发现macOS 版本Safari 浏览器中的严重漏洞，获奖10.5万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510357&idx=1&sn=4984145d8ed807424407baf582f63fe9&chksm=ea94983fdde311297a9060bb46db9abf15cfa7765bbd04e56316fbf902b432ad0799c02b88d2&scene=21#wechat_redirect)  
  
  
[一年太久，研究员决定不等补丁直接披露 Safari 0day 详情](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494803&idx=3&sn=13ef88778926d7f7b7346b97eda71504&chksm=ea94ddf9dde354ef42c7189c4d7c44c646ba6ed1a588bc427ed6ab2af9143f19acea0ad284b3&scene=21#wechat_redirect)  
  
  
[我一口气发现7个Safari  0day，苹果奖了7.5万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492659&idx=2&sn=f02fdcb2712b8f801247fd9525dc1062&chksm=ea94d559dde35c4f9211377c803a5e876b86061bd3b4e86da163c83aacdb914a77af11991483&scene=21#wechat_redirect)  
  
  
[苹果修复OS X 和Safari的0day漏洞，与NSO间谍软件有关](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485688&idx=1&sn=0440609d0932ce43b020d5d18e23232e&chksm=ea973992dde0b0842d0e34dee07543c44f1b0ef4004885c6f08b3ca8599b4e31992f74acc368&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/google-researchers-detail-5-year-old.html  
  
  
题图：  
Pixabay License  
‍  
  
  
  
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
