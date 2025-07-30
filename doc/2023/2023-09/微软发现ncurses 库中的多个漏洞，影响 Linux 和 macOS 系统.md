#  微软发现ncurses 库中的多个漏洞，影响 Linux 和 macOS 系统   
THN  代码卫士   2023-09-15 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**微软在ncurses 编程库中发现了多个内存损坏漏洞，可被用于在易受攻击的 Linux 和 macOS 系统上运行恶意代码。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ4WvWKdMGAUJsFrO8wzyP7jPmGCq3aNWcFT2niaHac5wOWebKxRGticRvCNCvbib1dsncLVg6VzdUlw/640?wx_fmt=gif "")  
  
  
微软威胁情报研究员 Jonathan Bar Or、Emanuele Cozzi 和 Michael Pearse 在一份技术报告中提到，“使用环境变量投毒，攻击者可组合利用这些漏洞实现提权并在目标程序的上下文下运行代码或者执行其它恶意操作。”这些漏洞的统一编号是CVE-2023-29491（CVSS评分7.8），已在2023年4月修复。微软表示已与苹果一起修复与这些缺陷相关的 macOS 漏洞。  
  
环境变量是用户定义的值，可由同一个系统上的多个程序使用并影响他们在系统上的行为方式。操纵变量可导致应用程序执行未授权操作。微软通过代码审计和模糊测试发现，该 ncurses 库搜索多种环境变量如 TERMINFO，进而投毒并通过组合其它漏洞实现提权。Terminfo 是一种数据库，可使程序以独立于设备的方式显示终端。  
  
这些漏洞包括栈信息泄露、参数化的字符串类型混淆、差一错误、Terminfo 数据库文件解析过程中的堆界外以及被取消字符串的拒绝服务。  
  
研究人员提到，“攻击者可利用所发现漏洞提权并在目标程序的上下文中运行代码。尽管如此，通过利用多个内存损坏漏洞获得对程序的控制需要多阶段攻击。攻击者需要组合利用这些漏洞提升权限，如利用栈信息泄露获得任意读原语，同时利用堆溢出获得写原语。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软 Azure FabricScape 漏洞可被用于劫持 Linux 集群](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512652&idx=2&sn=41462de310311abaadf3c81fa66dab19&chksm=ea948326dde30a30b6628410dbec18f7095b4ceac398685c020321f11a956d0d0c573779d4f5&scene=21#wechat_redirect)  
  
  
[Nimbuspwn：微软在Linux 操作系统中发现了多个提权缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511591&idx=1&sn=b2821056ec08d448999a6d1f0bc1c3a9&chksm=ea949f4ddde3165b34885b0802da21ef1ad96e1c18103920729d17fd3f3bb5a3fe24497b266b&scene=21#wechat_redirect)  
  
  
[微软在 Linux 虚拟机偷偷安装Azure App，后修复严重漏洞但Linux虚拟机难以修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507893&idx=1&sn=cefb593c11692ee3f342d9b62b7b0a57&chksm=ea94eedfdde367c91881b8cb4f1a6df580cad5473f0229907a438b507360a55692c73d304470&scene=21#wechat_redirect)  
  
  
[微软构建定制化 Linux 操作系统为物联网设备保驾护航](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486901&idx=1&sn=83f6556e92052e3c3b1e985f46836c9b&chksm=ea973cdfdde0b5c94a97157c377f16ece6e23406a4dbb9fe44b3963b5ff6cdca4506f4349bfd&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/09/microsoft-uncovers-flaws-in-ncurses.html  
  
  
题图：  
Pexels  
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
  
