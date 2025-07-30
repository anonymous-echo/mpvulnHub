#  DogWalk：Windows 新0day 获得非官方补丁   
Sergiu Gatlan  代码卫士   2022-06-08 18:17  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
微软支持诊断工具 (MSDT) 中存在一个新的Windows 0day，被戏称为 “DogWalk”，微软不打算修复，无CVE编号，目前0patch 平台发布补丁。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRBdf5RgjDIKuTmpIlrbg8nNTk662iaLdFjgqYTAibbAibcoqDzuMmicxBJ6YMW4D7cP6MthbmgR14r6Q/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRBdf5RgjDIKuTmpIlrbg8nGUHvzSrUPkd3oIDyal8ZuN2k11ksjCFkJmBbB6ib008vjjDLBNA1qGw/640?wx_fmt=gif "")  
  
**早在2020年1月就发现**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRBdf5RgjDIKuTmpIlrbg8nE3hUYw6zicRP0sqanQKw7NYgMZT6CtIHf8dfH3kBib91CVib6ricyMRwww/640?wx_fmt=png "")  
  
  
  
该漏洞是一个路径遍历漏洞。当目标打开恶意构造的 .diagcab 文件时（通过从邮件或web 下载接收）可被用于将可执行文件复制到 Windows Startup 文件夹中。之后，被植入的恶意可执行文件即可在受害者下次重启 Windows 时被执行。  
  
实际上，2020年1月，微软表示它并非安全问题因此不会修复时，安全研究员 Imre Rad 就曾公开披露该漏洞。不过最近另外一名研究员joosean 再次发现该漏洞，引发了新的关注。  
  
虽然微软表示因为.diagcab 文件被自动拦截，因此Outlook 用户并不处于风险之中，但安全研究员和专家表示利用该漏洞仍然是一个有效的攻击向量。例如，如果威胁行动者通过另外一个邮件客户端或通过受攻击者控制的站点在路过式下载中传播恶意文件，用户即可遭攻击。即使 .diagcab 文件是从互联网中下载的且包含一个 MOTW，但Windows 会忽视这种文件类型并在无警告的情况下允许打开文件。MOTW 属性供 web 浏览器和Windows 判断文件是否应当被视为可疑文件并忽视它，从而导致更多用户打开所下载文件。  
  
0patch 平台的联合创始人 Mitja Kolsek 解释称，“然而，Outlook 并未唯一一个传播渠道：此类文件可被所有主流浏览器下载，包括通过微软Edge浏览器，仅需访问一个网站，点击浏览器中的下载列表即可打开。在这个过程中并不会出现任何警告信息，这和下载并打开任何其它已知且能执行攻击者代码的文件的情况截然不同。”  
  
该漏洞影响所有的Windows 版本，包括最新发布 Windows 11 和 Server 2022 以及 Windows 7、Server 2008等等。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRBdf5RgjDIKuTmpIlrbg8nGUHvzSrUPkd3oIDyal8ZuN2k11ksjCFkJmBbB6ib008vjjDLBNA1qGw/640?wx_fmt=gif "")  
  
**非官方补丁**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRBdf5RgjDIKuTmpIlrbg8nE3hUYw6zicRP0sqanQKw7NYgMZT6CtIHf8dfH3kBib91CVib6ricyMRwww/640?wx_fmt=png "")  
  
  
  
在微软发布官方补丁之前，可使用0patch 平台推出的微补丁。该补丁适用于如下Windows 版本：  
  
- Windows 11 v21H2  
  
- Windows 10 (v1803 to v21H2)  
  
- Windows 7  
  
- Windows Server 2008 R2  
  
- Windows Server 2012  
  
- Windows Server 2012 R2  
  
- Windows Server 2016  
  
- Windows Server 2019  
  
- Windows Server 2022  
  
  
  
要安装这些补丁，用户需要注册一个0patch 账户并安装0patch 代理。启动该代理后，微补丁将自动应用，如不存在定制化打补丁拦截策略，则无需要求系统重启。  
  
Kolsek 补充道，“由于它是一个0day漏洞，不存在官方修复方案，因此在补丁出现之前，我们免费提供微补丁。我们不清楚该漏洞是否已遭在野利用或者将来是否会遭利用。但以曾经的攻击者身份而言，我们知道它是可以实际利用的问题，我们的微补丁确保0patch用户免除这些担心。”  
  
上个月，微软被迫公开关于Follina 漏洞的官方安全公告，而该公司此前拒绝相关漏洞报告，表示并非“安全问题”。该漏洞被活跃用于攻击美国和欧盟政府机构，0patch 当时也推出了非官方补丁。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[警惕！这个微软Office 0day 已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512040&idx=2&sn=471a3a8e0d63d1a8f6e3ef80341a47da&chksm=ea949e82dde3179403465e55b09d8a07b71abc9713b4e2d87959a9daf063f59c9b4fa6b6f4f1&scene=21#wechat_redirect)  
  
  
[微软发布5月补丁星期二，修复3个0day 且其中1个已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511765&idx=2&sn=b99fdd0a3b0bac32aa99cb67c1e0e960&chksm=ea949fbfdde316a964bdc0f19b319726b074bd9786990ab3462d6902d0d05c28778d0e5a1df4&scene=21#wechat_redirect)  
  
  
[微软4月补丁星期二修复119个漏洞，含2个0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511336&idx=1&sn=052c86709c4ddbf95f813c02e608dcdc&chksm=ea949c42dde315546c695a8137e97da6f7cde2c0e65f5c9c74129b2784ba7556109bdd14a192&scene=21#wechat_redirect)  
  
  
[开源U-Boot 引导加载程序中存在两个未修复的严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512136&idx=1&sn=f1dff2c42ec635a5e317f36ae18cc7f3&chksm=ea948122dde30834305c643105f82ae611aa4a5aefda16ea90c19b366b76a46bf19dfeb70686&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-dogwalk-windows-zero-day-bug-gets-free-unofficial-patches/  
  
  
  
题图：Pixab  
ay License  
  
  
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
