#  霍尼韦尔 Experion DCS 和 QuickBlox 服务中存在多个严重漏洞   
THN  代码卫士   2023-07-17 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Armis 公司的研究人员在霍尼韦尔 (Honeywell) Experion DCS 平台上发现了9个漏洞，如遭成功利用可导致受影响系统遭严重攻陷。这9个漏洞被统称为 “Crit.IX”。**  
  
这些漏洞可导致“越权远程代码执行后果，意味着攻击者可接管设备并修改 DCS 控制器的运营，使负责管理控制器的工程工作站无法看到这些修改。”换句话说，这些漏洞与用于 Experion Server 和 C300 控制器之间通信的专有协议“控制数据访问 (CDA)”中缺乏加密和适当的认证机制有关，可导致威胁行动者接管设备并修改 DCS 控制器的运营。  
  
Armis 公司的首席技术官 Tom Gol 指出，“因此，能够访问网络的任何人都能够模拟控制器和服务器。另外，CDA 协议中存在多个设计缺陷，使数据边界难以控制，从而导致缓冲区溢出后果。”  
  
CISA 发布安全公告指出，其中7个漏洞的CVSS评分为9.8，另外2个漏洞的评分为7.5，“漏洞如遭成功利用可导致决绝服务条件，从而导致权限提升或远程代码执行后果。”  
  
Check Point 和 Claroty 公司还在聊天和视频通话平台 QuickBlox 上发现了多个严重漏洞。QuickBlox 广泛应用于远程医疗、金融和智能物联网设备中。这些漏洞可导致攻击者泄露很多集成了 QuickBlox SDK 和 API的热门应用中的用户数据库。  
  
Rozcom 就是其中之一。这家以色列厂商出售民用和商用内部通话系统。进一步审计其移动应用后发现了其它漏洞（CVE-2023-31184和CVE-2023-31185），可下载所有用户数据库、模拟任意用户并执行完整的账户接管攻击。  
  
研究人员指出，“我们能够接管所有的 Rozcom 内部通话系统设备、获得完整控制权限并能访问设备摄像头和麦克风、窃取其推送内容并打开由设备管理的门。”  
  
本周还发现了影响 Aerohive/Extreme Networks 访问点的远程代码执行漏洞，这些访问点运行 HiveOS/Extreme IQ Engine 版本10.6r2 之前的版本和开源 Ghostscript 库（CVE-2023-36664，CVSS评分9.8），可导致远程命令遭执行。  
  
Kroll 公司的研究员 Dave Truman 表示，“Ghostscript 是使用广泛但不一定同样知名的程序包。它的执行方式很多，如在向量图像编辑器如 Inkscape 中打开文件、通过CUPS打印文件等，这意味着 Ghostscript 中的漏洞不止限于一款应用程序或显而易见。”  
  
基于 Golang 的开源平台 Owncast 和 EaseProbe 中也存在两个漏洞，它们分别是CVE-2023-3188（CVSS评分6.5）和CVE-2023-33967（CVSS评分9.8），可分别用于SSRF和SQL注入公积金。  
  
Technicolor TG670 DSL 网关路由器中存在硬编码凭据，可被认证攻击者获得对设备的完整管理员控制权限。CERT/CC在安全公告中提到，“远程攻击者可使用默认用户名和密码以管理员权限登录到路由器设备，从而导致攻击者修改路由器的任何管理员设置并以不同寻常的方式使用它。”  
  
建议用户禁用设备上的远程管理员权限，阻止潜在利用尝试并与服务提供商检查判断是否已存在正确的补丁和更新。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[谷歌安卓团队从霍尼韦尔设备中找到严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488085&idx=2&sn=bc9d2f493f3e3ee532051b17b7c75b6a&chksm=ea97233fdde0aa298fc5ee87aa2ae62990fe15534a5e43f6a211e5a41c7b651b1ae86e4774ce&scene=21#wechat_redirect)  
  
  
[霍尼韦尔物联网气体检测仪易受网络攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485836&idx=1&sn=9cbecd4fb628a60afed941c61401948c&chksm=ea9738e6dde0b1f04f23325dea257ae63f448997b4ea39b7bcb154680d427153d521743b71b8&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/07/critical-security-flaws-uncovered-in.html  
  
  
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
  
