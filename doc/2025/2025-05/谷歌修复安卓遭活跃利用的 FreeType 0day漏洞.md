#  谷歌修复安卓遭活跃利用的 FreeType 0day漏洞   
Bill Toulas  代码卫士   2025-05-07 10:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTTMhmvKE2iaicmgDxxvQAzfWviaYFhjcoUmlzPlXmh9AF597SPdHuXiaiahicTxWqhjsrjiaIReD9yZfDkQ/640?wx_fmt=png&from=appmsg "")  
  
  
**谷歌发布安卓2025年5月的安全更新，共修复45个漏洞，其中一个是已遭活跃利用的零点击 FreeType 2代码执行漏洞 CVE-2025-27363。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTTMhmvKE2iaicmgDxxvQAzfWR1mT8IVCqiaWHN01PgQc7sy2T0qibr10scw1yMFBgdQPXVYq7C4EQBJw/640?wx_fmt=png&from=appmsg "")  
  
  
FreeType 是一款热门的开源字体渲染库，能够显示并以编程的方式将文本添加至图像中。该漏洞CVE-2025-27363是一个高危的任意代码执行漏洞，由Facebook 公司的安全研究员在2025年3月发现。  
  
该漏洞影响 FreeType 2.13.0及之前的所有版本。该库发布安全通告提到，“有线索表明CVE-2025-27363可能已遭有限的针对性利用。”  
  
Facebook 和谷歌均为详细说明该漏洞如何遭利用的详情。然而，Facebook 公司在3月解释称，当FreeType 解析恶意TrueType GX 或可变的字体文件时，可导致代码执行。Facebook 公司提到，“当尝试解析与TrueType GX有关的字体子字形结构和和可变字体文件时，FreeType 2.13.0及以下版本（后续版本不受影响）中存在一个界外写漏洞。易受攻击的代码将有符号的短值分配给一个无符号的长值，之后增加一个静态值，导致回绕并分配过小的堆缓冲区。该代码随后写入相对于该缓冲区而言的长达6个有符号的长整数，这就可能导致任意代码执行后果。”  
  
谷歌本月还修复了其它漏洞，它们位于Framework，System，Google Play 和 Android Kernel 以及位于联发科、高通、Arm 和 Imagination Technologies 提供的专有组件中。  
  
安卓核心组件中的所有漏洞均被评级为高危，多数是提权漏洞。所发布修复方案与安卓版本13、14和15有关，尽管并非所有漏洞均影响这三个版本。  
  
安卓12在2025年3月31日已达支持期限，因此不再接受安全修复方案。然而，本次安全通告中的一些漏洞仍然影响12及更老旧版本。谷歌通常会通过 Google Play 系统更新频道为这些设备集成重要的修复方案，不过针对遭活跃利用的漏洞的特定修复方案不一定会应用到更老旧设备中。  
  
建议安卓13以下版本的用户考虑为不受支持设备集成了安全修复方案的第三方安卓发行版本，或者使用受原始设备制造商 (OEM) 支持的更新机型。用户可通过“设置＞安全和隐私＞系统和更新＞安全更新＞点击‘检查更新’”的流程（可能不同OEM/机型，流程有所不同）应用最新安卓更新。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Meta：FreeType 0day漏洞已遭活跃利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522499&idx=1&sn=6f07e20fe9fdb9cd65f9d65f779e0e37&scene=21#wechat_redirect)  
  
  
[CVE-2020-15999：Chrome FreeType 字体库堆溢出原理分析](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247496975&idx=1&sn=5c69254dfbb5bbaa3d544333c4f6052f&scene=21#wechat_redirect)  
  
  
[谷歌2024年检测到75个已遭利用0day，44%针对企业安全产品](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522916&idx=1&sn=bd784cba5a2043dfacb33dcf271ed806&scene=21#wechat_redirect)  
  
  
[谷歌修复GCP Cloud Run 中的提权漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522661&idx=2&sn=1f24df87fa44c9b3c92d7a7cdb139dd8&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭利用的0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522590&idx=2&sn=ee575193ee5fe0995b313a95a46890ee&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/google-fixes-actively-exploited-freetype-flaw-on-android/  
  
  
题图：  
Pixabay   
License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
