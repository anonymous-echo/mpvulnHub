#  苹果 “AirBorne” 漏洞可导致零点击 AirPlay RCE 攻击   
Sergiu Gatlan  代码卫士   2025-04-30 04:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**苹果 AirPlay 协议和 AirPlay 软件开发包 (SDK) 中存在多个漏洞，可导致未修复的第三方和苹果设备易受多种攻击，如远程代码执行等。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQBHP8w01yY1gL9rpuc1jequaWY7OGCWiaSXYicqmtQwY2XshgJXpPvBQ7OX3ovSWlfg1HYjPKwEfQg/640?wx_fmt=png&from=appmsg "")  
  
  
网络安全公司 Oligo Security 的安全研究人员发现并报送了这些漏洞，它们可用于零点击和一次点击RCE攻击、中间人攻击和DoS 攻击中，还可绕过访问控制列表和用户交互，获得对敏感信息的访问权限并读取任意本地文件。  
  
Oligo 公司共发现了23个漏洞，苹果在3月31日发布安全更新并将其修复且将它们统称为 “AirBorne”，已修复的设备和版本包括iPhone 和 iPad（iOS 18.4 和 iPadOS 18.4）、Macs（macOS Ventura 13.7.5、macOS Sonoma 14.7.5和 macOS Sequoia 15.4）以及Apple Vision Pro (visionOS 2.4) 设备。苹果公司还修复了AirPlay音频SDK、AirPlay 视频SDK和CarPlay 通信插件。  
  
虽然AirBorne 漏洞仅可由位于同样网络的攻击者通过无线网络或端对端连接进行利用，但可用于接管易受攻击的设备并将其访问权限作为攻陷同样网络上其它启用 AirPlay 的设备的启动面板。  
  
安全研究人员表示他们能够证明，攻击者能够利用其中的两个漏洞CVE-2025-24252和CVE-2025-24132创建可蠕虫的零点击 RCE 利用。此外，CVE-2025-24206用户交互绕过漏洞可导致威胁人员绕过 AirPlay 请求上的“接受”点击要求并可与其他漏洞组合用于发动零点击攻击。  
  
Oligo 公司提醒称，“这意味着攻击者可接管某些启用 AirPlay 的设备并执行多种操作，如部署恶意软件，可传播到与受感染设备连接的任何本地网络上的设备，从而导致其它复杂攻击如间谍、勒索软件、供应链攻击等。”  
  
该公司提到，“由于AirPlay 是苹果设备和使用 AirPlay SDK的第三方设备的根本性软件，因此这类漏洞可造成深远影响。”  
  
该公司建议组织机构立即将任何企业苹果设备和启用 AirPlay 的设备更新至最新软件版本并要求员工同时更新所有的个人 AirPlay 设备。用户可采取的其它减小攻击面的措施包括：将所有苹果设备更新至最新版本、如不使用 AirPlay 接收器则禁用、通过防火墙规则仅限可信设备访问 AirPlay、以及通过仅允许当前用户使用 AirPlay 减小攻击面。  
  
苹果表示，全球拥有超过23.5亿台活跃的苹果设备，Oligo 公司预计受 AirPlay 支持的第三方音频设备如扬声器和电视达到数千万台，而其中尚不包括支持 CarPlay 的汽车信息娱乐系统。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[我俩也组了个队，找到一个苹果RCE 0day，获 $5 万奖金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247500513&idx=1&sn=07dcd0f2530282530f7f30c374bb0ce7&scene=21#wechat_redirect)  
  
  
[华为苹果三星等均受影响：博通 WiFi 驱动被曝漏洞，可导致 RCE 和 DoS](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489762&idx=2&sn=74a7aa82de7def2e844ab6dff1b8d8ff&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的两个0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522769&idx=1&sn=665091a9de4302af67ecf646d9c5bb79&scene=21#wechat_redirect)  
  
  
[苹果紧急修复被用于“极其复杂”攻击中的0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522200&idx=2&sn=a8084137286ce6cbebda935ab8c0d5c2&scene=21#wechat_redirect)  
  
  
[谷歌修复由苹果报送的严重 Chrome 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521342&idx=1&sn=355a1e1a938422e3437d8a957f360c7e&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/apple-airborne-flaws-can-lead-to-zero-click-airplay-rce-attacks/  
  
  
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
  
