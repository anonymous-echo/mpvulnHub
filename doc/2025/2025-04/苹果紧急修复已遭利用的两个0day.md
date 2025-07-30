#  苹果紧急修复已遭利用的两个0day   
Lawrence Abrams  代码卫士   2025-04-17 09:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**苹果发布紧急安全更新，修复了可用于攻击特定目标 iPhone 的“极其复杂攻击”中的两个0day漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQw3vSZiagbTLlKoYKI9OKZxruCY1rchqGnkibQp0Haqib4HFhLvod5NIzkZrGas1ibCVJAHm8H6IXCMQ/640?wx_fmt=png&from=appmsg "")  
  
  
这两个漏洞位于 CoreAudio (CVE-2025-31200) 和 RPAC (CVE-2025-31201) 中，均影响 iOS、macOS、tvOS、iPadOS 和 visionOS。苹果公司在今天发布的安全通告中提到，“苹果发现有报告称该问题已被用于针对iOS 上特定目标个体的极其复杂的攻击中。”  
  
CVE-2025-31200位于 CoreAudio 中，由苹果和谷歌威胁分析团队发现，它可通过处理恶意构造的媒体文件中的音频流遭利用，在设备上执行远程代码。CVE-2025-31201是由苹果公司发现的，位于 RPAC 中，可导致具有读或写权限的攻击者绕过 iOS 用于防护内存漏洞的的一个安全特性 PAC。  
  
苹果并未分享更多关于这些漏洞如何遭利用的详情。苹果和谷歌也并未就相关提问给出回复。这两个漏洞均已在 iOS 18.4.1、iPadOS 18.4.1、tvOS 18.4.1、macOS Sequoia 15.4.1和 visionOS 2.4.1中修复。  
  
受这两个0day 漏洞影响的设备数量庞大，新旧型号均受影响：  
  
- iPhone XS 及后续版本  
  
- iPad Pro 13英尺、iPad Pro 13.9英尺第三代及后续版本、iPad Pro 11英尺第一代及后续版本、iPad Air 第三代及后续版本、iPad 第七代及后续版本以及iPad mini第五代及后续版本。  
  
- macOS Sequoia  
  
- Apple TV HD 和 Apple TV 4K（所有型号）  
  
- Apple Vision Pro  
  
  
  
尽管这些0day 漏洞已用于高度针对性的攻击活动中，仍强烈建议用户尽快安装补丁。加上这两个漏洞，苹果在今年已修复五个0day漏洞，其它三个分别是1月份修复的CVE-2025-24085、2月份修复的CVE-2025-24200以及3月份修复的CVE-2025-24201。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果紧急修复已遭利用的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522462&idx=1&sn=c051df72b6c28d0692307dd16d721ac3&scene=21#wechat_redirect)  
  
  
[苹果紧急修复被用于“极其复杂”攻击中的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522200&idx=2&sn=a8084137286ce6cbebda935ab8c0d5c2&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的两个0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521533&idx=1&sn=1ab7c5da3e583e48ee67d6f50fd4d97e&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的两个新 iOS 0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519003&idx=1&sn=87b2f80deede9f2cb8e1092e9732820f&scene=21#wechat_redirect)  
  
  
[苹果修复2024年遭利用的第1个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518729&idx=1&sn=022dec20b1d19ed71466fd78c5c9b7c1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/apple-fixes-two-zero-days-exploited-in-targeted-iphone-attacks/  
  
  
  
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
  
