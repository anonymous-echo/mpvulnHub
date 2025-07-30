#  0day 可导致设备遭远程攻陷 贝尔金不打算修复   
KEVIN PURDY  代码卫士   2023-05-17 16:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**以前我（本文作者，下同）曾共有一个合作办公空间。门锁是磁力锁，通过电源中继器解锁。我们发现，如果能够控制系统电源的开源，就可以远程控制门锁。我们两人之中有一个拥有第一代贝尔金 Wemo 插座，于是我们安装好，然后两人中的程序员设置了一个脚本，在本地网络传递 Python 命令，控制门锁的开关。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMS69gXj1Xiawtn7dTtuQVhOECWumxHGfpRRoArIKibE5k4ty45pzsdw45MkIzxfwMJCicicuTfWa8NYXw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS69gXj1Xiawtn7dTtuQVhOEMEzsyGmYQKCibxNXdoJ59ibAdJZIElLzLW6czGy0Hygh3D4bqtrMHrSg/640?wx_fmt=png "")  
  
  
有时候我会觉得有点诡异，没有认证就能够在 Wemo 中写入 Python 命令，然后还能切换。而现在对于更新一代也存在致命缺陷的设备我也是同样的感觉。  
  
物联网安全研究企业 Sternum 发现并披露了位于 Wemo 迷你智能插座 V2 中的一个缓冲区溢出漏洞。博客文章中写满了关于该设备如何运作（和不运作）的有趣细节，但一个关键要点是可以通过第三方工具向设备发送长于30字符限制的名称，就能触发缓冲区溢出。这个限制是 Wemo 应用自身执行的。在这个溢出中可以注入可操作代码。如果 Wemo 和更广泛的互联网联网，那么就可以遭远程攻陷。  
  
另外一个关键要点是，Wemo 的制造商贝尔金向 Sternum 表示，将不会修复该漏洞，因为迷你智能插座 V2“正处于生命晚期，因此该漏洞将不会被修复。”贝尔金目前尚未就此事志平。Sternum 公司声称已在1月9日将问题告知贝尔金并在2月22日收到回复，之后在3月14日披露了该漏洞。  
  
Sternum 公司建议避免在更广阔的互联网中暴露任何一个单元，如有可能则将其分割到远离敏感设备的子网中。然而，通过 Wemo 基于云的接口可触发漏洞。  
  
该漏洞存在的原因是社区应用 pyWeMo （是我上面提到的合作空间所使用版本的更新分叉）。更新一代的 Wemo 设备提供了更多特性，但仍然在无需密码或认证的情况下对从 pyWeMo发送的网络命令进行相应。  
  
贝尔金公司的 Wemo 设备曾经就引发智能家庭安全问题。2014年2月，安全研究员披露称其设备通过一个固件更新工作流泄漏密码；比尔金表示已经在固件更新中修复该问题，但似乎并未告知最初的问题报告研究员或者 US-CERT（即网络安全和基础设施安全局 CISA）。2019年，研究员报告称一年前报告给贝尔金的漏洞仍然还未修复。  
  
易受攻击的 Wemo 插座是当时可用的最流行和最简单的一类插座，得到很多智能家庭指南的推荐，而且从评价来看，购买用户数有数千人。虽然在2019年上市，但并非智能手机或平板。四年之后，直到现在人们才开始考虑不使用该设备。  
  
我自己家里就有几个这类设备，用来做一些单调的事情如，“日落时打开楼梯上的串灯，在晚上10点关闭”，以及“我不想起床时打开白噪音机器”。如果这些命令通过我所在区域的电子垃圾工厂切碎并归类到金属成分后，就不会遭到远程代码执行攻击。  
  
有一个办法可帮助 Wemo 设备消除暴露在互联网中的漏洞和到期不再支持的问题，那就是通过 Matter 仅提供本地支持。然而，贝尔金目前还没有采用 Matter 支持的打算，表示“找到区分方法后”，会在 Wemo 产品中提供这种支持。至少，贝尔金现在以一种值得注意的方式表示，未来产品可能会有所不同了。  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[ÆPIC Leak：英特尔CPU中的架构漏洞泄露机密数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513509&idx=2&sn=b745758188993ff6e6d51a4ac6dfb3a5&chksm=ea9484cfdde30dd96a8bc16bc1440917d0346f87c82b9669b457494dfc81f9637a6810cb4bd6&scene=21#wechat_redirect)  
  
  
[Retbleed：针对英特尔和AMD处理器的推断性执行攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512889&idx=3&sn=645a6adc37050f76571e2cf1043659e9&chksm=ea948253dde30b45023fc8b066c2420844a7cfd7b7197f46be2df789dea706f9e2ec61674969&scene=21#wechat_redirect)  
  
  
[多个高危 BIOS 缺陷影响英特尔处理器，特斯拉 Model 3 未幸免，可用于供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509217&idx=1&sn=76e305d3e8e35306190769afbb916540&chksm=ea94958bdde31c9dc3c4c9d0061c2b8f2a499058261829bf2fa0afb964d14d7470635e1937cb&scene=21#wechat_redirect)  
  
  
[微软、英特尔和高盛牵头成立供应链安全工作组](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508450&idx=3&sn=1e8542618ac059d549fecdc9c497f2be&chksm=ea949088dde3199ef460da31580a3bfb7166d1e141fa393f476e6fa1cffd52f341fa37365732&scene=21#wechat_redirect)  
  
  
[比 Meltdown 和 Sepctre 更凶险：四个 CPU 新缺陷影响几乎所有英特尔处理器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489946&idx=1&sn=68f88e4374bceeabcd4d512b9bf5dd4b&chksm=ea9728f0dde0a1e64626666f36b4c110c74e194548d7c0005986aade7ae2fc59d7cc49a0d030&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.theregister.com/2023/05/15/intel_mystery_microcode/  
  
  
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
  
