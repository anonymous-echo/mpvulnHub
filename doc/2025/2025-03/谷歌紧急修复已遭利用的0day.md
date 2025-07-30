#  谷歌紧急修复已遭利用的0day   
Ravie Lakshmanan  代码卫士   2025-03-26 18:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌发布带外修复方案，修复了位于Windows 版本 Chrome 浏览器中已遭利用的高危漏洞。该漏洞被用于攻击俄罗斯的组织机构。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQjsAJ7iaX1kH2GH6cYn58icGV5BywFXP63ibOKxIY6Jjsny8jCt9InCW6Y2kDW5LGavHEKrCukcx8Dw/640?wx_fmt=png&from=appmsg "")  
  
  
该漏洞的编号是CVE-2025-2783，是“对Windows 上 Mojo 中未明确情境中提供的错误句柄”情况。Mojo 是指为进程间通信 (IPC) 提供与平台无关机制的运行时库集合。  
  
按照管理，谷歌并未提供关于攻击性质的其它技术详情、攻击者身份以及受攻击的目标。该漏洞已在Windows版的 Chrome 134.0.6998.177/.178中修复。谷歌表示，已发现该漏洞遭利用的报告。  
  
值得注意的是，CVE-2025-2783是2025年以来首个遭活跃利用的 Chrome 0day漏洞。卡巴斯基实验室的研究人员 Boris Larin 和 Igor Kuznetsov 发现并在2025年3月25日报送。  
  
卡巴斯基实验室在安全通告中将该漏洞的利用视为技术复杂的针对性攻击，说明为APT组织所为。该实验室将其命名为 “Operation ForumTroll”。研究人员提到，“在所有情况中，感染是在受害者点击钓鱼邮件中的连接后立即发生的，攻击者的网站通过 Chrome 浏览器打开，无需任何其它操作即可导致受害者受感染。该漏洞的核心在于 Chrome 和 Windows 操作系统的交集的逻辑错误，可导致浏览器的沙箱防护措施遭绕过。”  
  
这些短时间存在的链接据称是为受害者量身定制的，而最终目标是实施监控。卡巴斯基实验室表示这些恶意邮件中包括据称来自合法科学和专家论坛 Primakov Readings 的组织者发出的邀请函中。  
  
这些钓鱼邮件针对位于俄罗斯的媒体、教育机构和政府组织机构。另外，CVE-2025-2783旨在与可导致RCE后果的其它利用组合使用。卡巴斯基表示未能获得第二个利用。研究人员表示，“截止目前所分析的所有攻击工件表明攻击者的高度复杂性，让我们有信心认为幕后黑手是受国家支持的APT组织。”  
  
鉴于漏洞已遭活跃利用，建议使用基于 Chromium 浏览器如微软 Edge、Brave、Opera和Vivaldi 的用户也及时应用修复方案。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Chrome 修复 Lens 特性中的严重 UAF 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522548&idx=2&sn=0cc9b1e732d2a5c231ebd3f08b1198d4&scene=21#wechat_redirect)  
  
  
[谷歌2024年发放1200万美元漏洞赏金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522450&idx=2&sn=07fb2382932a5afdd7e28086180274bc&scene=21#wechat_redirect)  
  
  
[谷歌OAth 漏洞导致弃用账号遭访问](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522104&idx=1&sn=c06ab4d6c64169ea92baf711cd9ca06f&scene=21#wechat_redirect)  
  
  
[谷歌AI平台存在漏洞，可泄露企业的专有LLMs](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521484&idx=1&sn=19327f5e0d0275273114fd7a7e37da3f&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/zero-day-alert  
-google-releases-chrome.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
