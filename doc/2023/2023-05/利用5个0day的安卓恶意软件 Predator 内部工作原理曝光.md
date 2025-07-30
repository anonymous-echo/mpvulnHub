#  利用5个0day的安卓恶意软件 Predator 内部工作原理曝光   
DAN GOODIN  代码卫士   2023-05-29 17:50  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**思科 Talos 安全团队的研究人员发现，销往全球各国政府的智能手机恶意软件Predator可秘密记录语音通话和附近音频、从各种应用如 Signal 和 WhatsApp 中收集数据，并隐藏应用或阻止它们在设备重启时运行。**  
  
  
  
  
研究员发布分析指出，Predator 是一款适用于安卓和 iOS 移动设备的高阶监控软件。Predator 由 Cytrox 开发，后者被公民实验室指为联盟 Intellexa 的一个组成部分，“（联盟）出现在2019年，是一系列监控厂商的营销标签”。这一联盟中的其它企业还包括 Nexa 技术公司（此前被称为 Amesys）、WiSpear/Passitora 有限公司以及 Senpai。  
  
去年，谷歌威胁分析组织的研究人员报道称，Predator 将五个0day exploit 打包到一个程序包中，并将其出售给多个受政府支持的行动者。这些买家将该 exploit 用于三起不同的攻击活动中。研究人员表示，Predator 与名为 Alien 的组件密切协作，该组件“位于多个权限进程中并接收来自 Predator 的命令”。这些命令包括记录音频、增加数字化证书以及隐藏应用。  
  
同时，公民实验室表示，Predator 被出售给多个政府行动者，包括亚美尼亚、埃及、希腊、印度尼西亚、马达加斯加、欧曼、沙特阿拉伯以及塞尔维亚。公民实验室还提到，Predator 用于攻击埃及反对党成员、流放在土耳其的 Ayman Nour，以及一名流放在外的主持一档热门新闻节目的记者（希望匿名）。  
  
  
**内部运作原理公开**  
  
  
Predator 的多数内部运作原理此前均不为人所知。这一切随着Talos 获得为安卓设备编写的关键部分后发生了改变。  
  
研究人员指出，Predator 的主干部分是 Predator 和 Alien。与此前的理解不同，Alien 不仅仅是 Predator 的加载器，它活跃地执行着 Predator 需要监视受害者的各种底层能力。  
  
研究报告中剃刀，“Talos 最新分析发现了PREDATOR的内部运作原理及其用于和其它监控软件组件ALIEN通信的机制。这两个组件协同运作，绕过安卓操作系统上的传统安全特性。我们的研究结果表明，PREDATOR和ALIEN之间的能力交叉程度，证明了ALIEN远不止是原先认为的 PREDATOR 的加载器这么简单。”  
  
在研究人员分析的样本中，Alien 利用五个漏洞CVE-2021-37973、CVE-2021-37976、CVE-2021-38000、CVE-2021-38003和CVE-2021-1048控制目标设备，其中前四个漏洞影响 Google Chrome，最后一个漏洞影响 Linux 和安卓。  
  
Alien 和 Predator 联手协作绕过安卓安全模型中的限制条件，最引人注意的是由防御措施 SELinux 执行的限制条件。安卓上的 SELinux 密切保护对多数套接字的访问权限，而这些套接字是多种运行进程之间的通信渠道，经常遭恶意软件滥用。  
  
其中一种方法是将 Alien 加载到为 Zygote64 保留的内存空间中，这是安卓用于启动应用的方法。这种方法可使恶意软件更好地管理被盗数据。研究人员指出，“通过ALIEN 将所记录的音频存储在共享内存区域，之后将其保存在磁盘中并通过PREDATOR进行提取，从而绕过该限制。这是该进程的简化版，需要记住的是ALIEN被注入 zygote 地址空间，以跳转到安卓权限模型中的特定权限进程。由于 zygote 是多数安卓进程的父进程，它可更改为多数 UID 中并转变到处理不同权限的其它 SELinux 上下文中。因此，这就使 zygote 成为要求多种权限的操作的很好的目标。”  
  
Predator 依赖于两种更多的组件：  
  
- Tcore 是主要的组件并包含核心的监控软件功能。监控能力包括记录音频并收集来自 Signal、WhatsApp 和 Telegram 以及其它应用的信息。外围功能包括隐藏应用并阻止应用在设备重启时执行的能力。  
  
- Kmem 提供对内核地址空间的任意读和写权限。这种权限是通过 Alien 利用CVE-2021-1048导致的，可使监控软件执行多数函数。  
  
  
  
对Predator 的深入分析将有助于工程师构建更好的防御措施，检测 Predator 监控软件并阻止它按设计运行。研究人员无法获得为 iOS 设备开发的 Predator 版本。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌推出安卓应用奖励计划，最高赏金3万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516557&idx=1&sn=c5b0b33ec535dbef4720e3ee78d2af0a&chksm=ea94b0e7dde339f157a4a05676f75b42a307ecc12eaeddf553d77f0763783564b7f1d2ff9376&scene=21#wechat_redirect)  
  
  
[商业监控软件厂商利用多个0day 攻击安卓和 iOS 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516096&idx=1&sn=1b7557f7a2683f3f9e215004fb1e4922&chksm=ea948eaadde307bc2c035530c28e9af2f550d85dccbde7413bdd71c3c755aeaea56acc4d9dc4&scene=21#wechat_redirect)  
  
  
[Chromium 漏洞可用于绕过安卓设备上的安全特性](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515762&idx=2&sn=d0544e7c040ded8d269077260cf6dd17&chksm=ea948f18dde3060e3aeb1b186df35346212a396dafcdc58377d0aad3d492d5483edf1b72a7cb&scene=21#wechat_redirect)  
  
  
[补丁延迟导致数百万台安卓设备易受攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514727&idx=2&sn=248651ac7d2ceefc9c0c049af0961e9b&chksm=ea948b0ddde3021b4df5688ce372eaee65c7f35e447bcbd7e81112b03f9383d6f6127a80b6b0&scene=21#wechat_redirect)  
  
  
[亚马逊悄悄修复安卓相册 app 中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512652&idx=3&sn=2b4e8e13ba0800dd1fc7f8468b6a0829&chksm=ea948326dde30a308994628b3b2468662db78d6469ed717a69fd91089fce0e26e5820559f664&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://arstechnica.com/gadgets/2023/05/a-decade-after-it-mattered-windows-xps-activation-algorithm-is-cracked/  
  
  
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
  
