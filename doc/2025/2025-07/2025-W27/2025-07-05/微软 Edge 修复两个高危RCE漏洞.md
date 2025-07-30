> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523450&idx=1&sn=fb41027f31142b3eef6b9494edc4b71e

#  微软 Edge 修复两个高危RCE漏洞  
Ddos  代码卫士   2025-07-04 10:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**微软发布 Edge 稳定版本138.0.3351.65，修复了影响基于 Chromium 的 Edge 浏览器中有三个高危漏洞，其中一个已遭在野利用，另外一个可通过构造的用户交互触发远程代码执行 (RCE)。**  
  
CVE-2025-6554由 Chromium 安全团队发现且已遭活跃利用，它是位于 V8 JavaScript 引擎中的类型混淆漏洞。该漏洞可导致恶意网站操纵内存边界，使攻击者读或写任意内存位置，从而导致沙箱逃逸、信息盗取甚至是远程代码执行，具体取决于该漏洞的利用方式。  
  
除此以外，微软还修复了Edge 中存在的漏洞CVE-2025-49713，CVSS评分8.8。攻击者如能诱骗用户点击恶意链接或打开受陷附件，则可执行远程代码。微软解释称，“该攻击要求认证客户点击一个链接，使未认证攻击者触发远程代码执行。”  
  
该攻击场景体现了社工技术：攻击者发送钓鱼邮件、即时消息或文档，诱骗用户加载恶意站点。一旦诱骗成功，攻击者可在受害者机器上执行任意代码，可能安装恶意软件、窃取凭据或在企业网络内跳转。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软 Edge 被指将用户访问的站点发送给Bing](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516356&idx=2&sn=a80a338de7f5bf0f3031105e790dd2d2&scene=21#wechat_redirect)  
  
  
[微软 Edge bug 导致黑客窃取用户在任意站点的机密信息，颁发2万美元奖金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506050&idx=1&sn=3f712007252c75c87bc07476284e1575&scene=21#wechat_redirect)  
  
  
[影响 Chrome、Edge 等浏览器的 V8 引擎0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503384&idx=1&sn=9a67b0bee113fbb969df0388706e64a7&scene=21#wechat_redirect)  
  
  
[微软推出 “Edge 漏洞研究计划”，类似于谷歌的 Project Zero 项目](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495746&idx=3&sn=c4afda3debc3566766716b3619b61b30&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/07/critical-cisco-vulnerability-in-unified.html  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
