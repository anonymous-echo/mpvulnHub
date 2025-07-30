#  新型侧信道漏洞 Hertzbleed 影响所有AMD 和 Intel CPU   
Ravie Lakshmanan  代码卫士   2022-06-16 17:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMR7KiacWEBZZA4yn069ibzKo57BYPB1nQR9RVZW10g13tmTg05SsY3ZYKJbxVNOo8bBldoMkUGloATA/640?wx_fmt=png "")  
  
现代Intel 和AMD处理器中出现一个新漏洞，可导致远程攻击者通过功率侧信道攻击窃取加密密钥。该漏洞被研究员命名为 “Hertzbleed”。  
  
  
  
研究人员指出，该漏洞根植于热功耗管理特性动态电压频率调整 (DVFS)中。DVFS用于节约用电并减少芯片产生的热量。他们表示，“原因在于，在某些情况下，定期的CPU频率调整取决于当前的CPU功耗，这些调整直接转换为执行时间差异（如1赫兹 = 1周秒）。” 即使作为常数时间代码正确执行阻止基于定时的侧信道，这就会对加密库造成重大安全风险，从而导致攻击者利用执行时间差异提取敏感信息如加密密钥。  
  
AMD 和 Intel 均发布安全公告（AMD：CVE-2022-23823和Intel：CVE-2022-24436），而Intel 表示所有Intel 处理器均受 Hertzbleed 漏洞影响。目前尚无补丁。  
  
AMD 表示，“由于该漏洞影响具有基于功耗分析的侧信道泄露的加密算法，因此攻击者可对算法的软件代码应用应对措施。可通过掩蔽、隐藏或密钥修改方式缓解该攻击。”  
  
虽然上不存在补丁，但Intel 建议加密开发人员按照指南加固库和应用程序的安全，应对频率调整信息泄露。  
  
这并非研究员首次发现可从Intel 处理器中嗅探数据的新型方法。2021年3月，Hertzbleed 的两名合著者展示了“片上跨内核”侧信道攻击针对Intel Coffee Lake 和 Skylake 处理其中使用的环形互联。  
  
研究人员总结称，“我们获得的启示是当前关于如何写常数时间代码的加密工程实践已不足以保证在现代的变量频率处理器上执行软件常数时间。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Intel CPU 易受新型的 SGAxe 和 CrossTalk 侧信道攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493460&idx=3&sn=a497933f6461207b2df59091f67d83fd&chksm=ea94d63edde35f280e3974e748b8a3d552c82e6b0b75663dc17608cd56f55a04af83a545d819&scene=21#wechat_redirect)  
  
  
[新型侧信道攻击从 Windows 和 Linux 页面缓存中窃取数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488917&idx=1&sn=21c491ae481216deed66294fea3a2783&chksm=ea9724ffdde0ade90a89522d136b7c6023c7d66d2a7115167450c6a372001f1e468479022098&scene=21#wechat_redirect)  
  
  
[新型侧信道攻击利用麦克风读取屏幕内容](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487893&idx=1&sn=381ca7ca139b1c47f5727818ef07ff87&chksm=ea9720ffdde0a9e9e9ca16940b10c030366c791e787777e38f5916f0aed6f4071dbe1e42b8d7&scene=21#wechat_redirect)  
  
  
[新型 CPU 侧信道攻击 SpectreRSB 现身](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487666&idx=3&sn=848b874df261b4b200028f9d6d210d4d&chksm=ea9721d8dde0a8ce538f1272c97be75d2f18565435265fe806e2a0263b38f4d7f6ecd527e2d8&scene=21#wechat_redirect)  
  
  
[英特尔 CPU 被曝易遭 BranchScope 侧信道攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486762&idx=2&sn=a2c437b9e9bfbb966557c1d02923c72e&chksm=ea973c40dde0b5568cc370c33b3dc859ca2fb77dc002c1223a42011bc981cb7afe8553e9ba5d&scene=21#wechat_redirect)  
  
  
[Intel、AMD和Arm 告警：注意新的推断执行CPU漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510855&idx=3&sn=5ebfde6f449e166adf5d37e1ab3461bf&chksm=ea949a2ddde3133b97ff80f34174a773d2da203fa22dde34d8eee14e346d0391dd1c652afad3&scene=21#wechat_redirect)  
  
  
[AMD 证实处理器漏洞报告完全属实 将在数周内推出补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486709&idx=3&sn=18e005ec59ee58e914f2a0c08589c12c&chksm=ea973d9fdde0b4893518ed52bc55b59e1fcfe309806255bd01926859bf4cc3f3cf20516bcfff&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/new-hertzbleed-side-channel-attack.html  
  
  
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
