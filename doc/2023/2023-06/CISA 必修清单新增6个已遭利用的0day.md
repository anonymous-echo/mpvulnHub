#  CISA 必修清单新增6个已遭利用的0day   
Ravie Lakshmanan  代码卫士   2023-06-26 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**美国网络安全基础设施安全局 (CISA) 在“已知已遭利用漏洞”分类表中新增了6个漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMT8fhontArmrwS6EBE6o6ibvcyjUr9b4rSHwSYFiaLo4Nbvu3TVZjqoysMTbmNRRJ6SXSuqMhIJ8Agg/640?wx_fmt=png "")  
  
  
这6个漏洞分别是苹果公司在本周修复的3个漏洞（CVE-2023-32434、CVE-2023-32435和CVE-2023-32439）、位于 VMware 中的两个漏洞（CVE-2023-20867和CVE-2023-20887）以及位于 Zyxel 中的一个漏洞（CVE-2023-27992）。  
  
CVE-2023-32434和CVE-2023-32435均可导致代码执行后果，据报道已被用于始于2019年的网络监控活动中。这起攻击活动被称为“三角定位行动 (Operation Triangulation)”，旨在部署可从受陷设备中提取大量信息的 TriangleDB，如创建、修改、删除和盗取文件，列出并终止进程，从 iCloud Keychain 中收集凭据以及追踪用户位置等。  
  
该攻击链始于目标受害者接收到带有附件的 iMessage，在无需任何交互的情况下自动触发 payload 执行，使其成为零点击利用。卡巴斯基在最初的报告中提到，“恶意信息是畸形的，不会为用户触发任何报警或通知。”  
  
CVE-2023-32434和CVE-2023-32435是被滥用于监控攻击中很多 iOS 漏洞中的两个。其中一个是CVE-2022-46690，它是位于 IOMobileFrameBuffer 中的一个高危界外读漏洞，可被恶意 app 武器化，利用内核权限执行任意代码。该漏洞已由苹果公司在2022年12月通过改进输入验证而修复。  
  
卡巴斯基将 TriangleDB 标记为包含无用特性，引用 macOS 以及各种权限，访问设备的麦克风、摄像头和地址簿，可供后续使用。调查始于今年年初，当时卡巴斯基检测到自家企业网络中的攻陷情况。  
  
鉴于漏洞已遭活跃利用的情况，联邦民用行政部门 (FCEB) 被建议应用厂商提供的补丁，保护网络免受潜在威胁。  
  
前不久，CISA 发布警报，提醒 BIND 9 DNS 软件套件中存在3个漏洞，可触发拒绝服务条件。这3个漏洞是CVE-2023-2828、CVE-2023-2929和CVE-2023-2911，它们可遭远程利用，导致named BIND9 服务异常终止或运行named 的主机可用内存耗尽，从而导致 DoS。这是不到6个月内，ISC 第二次发布补丁修复 BIND9 中可引发 DoS 和系统失败等类似问题。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[CISA提醒：严重的 Ruckus 漏洞被用于感染 WiFi 接入点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516487&idx=2&sn=a0bd3a1e5ae0747b856ff42a50636fa1&chksm=ea94b02ddde3393b8a0a1ef90ddb1b3ee7f686b99ca6be0fbe36815c0c1d139cd46fda753f61&scene=21#wechat_redirect)  
  
  
[1500万公开服务易受 CISA 已知已遭利用漏洞攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516131&idx=2&sn=e4062667fe1d4694a90a9ffa17a2fd40&chksm=ea948e89dde3079ffc2cbba3e2f13e7929117094754c9e3216a4c6cb5f303cf622ec99800e6b&scene=21#wechat_redirect)  
  
  
[CISA紧急提醒：Adobe ColdFusion漏洞已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515947&idx=3&sn=76c36938bf1b7401950fc62730020638&chksm=ea948e41dde30757c6826cbbaeba673c04d191b437bd8a20532e2a13614e94562772ade4c057&scene=21#wechat_redirect)  
  
  
[CISA提醒注意与LastPass泄露事件有关的Plex漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515912&idx=2&sn=9a2496bb8c17bcf9ed8e477367f18001&chksm=ea948e62dde307749ef7616c97efc1c91e680e87bd654e1a1766fae70831f36318fa216354cf&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/06/us-cybersecurity-agency-adds-6-flaws-to.html  
  
  
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
  
