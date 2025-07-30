#  华硕修复严重的DriverHub 漏洞   
Ravie Lakshmanan  代码卫士   2025-05-13 10:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**华硕发布更新，修复了影响DriverHub 的两个漏洞。这两个漏洞如遭成功利用，可导致攻击者利用 DriverHub 实现远程代码执行。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMT2jXU8n39gJvH7gK28Yz6BGfNrbOmzuPsOoDv5S9Qb4sk7yRwvWIckMFdibtpUChCxYicJfyULvibGg/640?wx_fmt=png&from=appmsg "")  
  
  
DriverHub 工具旨在自动检测计算机的主板型号，通过与托管在 “driverhub.asus[.]com” 上的一个专门网站通信，为后续安装展示必要的驱动更新。这两个漏洞概述如下：  
  
- CVE-2025-3462（CVSS 8.4）：该来源验证错误漏洞可导致越权攻击者通过构造的HTTP请求与DriverHub 的特性进行交互。  
  
- CVE-2025-3463（CVSS 9.4）：该证书验证不当漏洞可导致不可信来源通过构造的HTTP请求影响系统行为。  
  
  
  
这两个漏洞是由安全研究员 MrBruh 发现并报送的，他表示这两个漏洞可被用于实现远程代码执行后果，作为一次点击攻击活动的一个组成部分。  
  
该攻击链主要涉及诱骗一个毫不知情的用户访问 driverhub.asus[.]com 的子域名，之后利用 DrvierHub 的 UpdateApp 端点来执行 “AsusSetup.exe”二进制的合法版本，运行托管在虚假域名上的任意文件。  
  
研究员在一份技术报告中提到，“执行 AsusSetup.exe时，它首先从 AsusSetup.ini 中读取，其中包括关于该驱动的元数据。如果运行带有“–s”标记的AsusSetup.exe，则它会执行 SilentInstallRun 中指定的任何东西。在本例中，ini 文件指定了一个 cmd 脚本可执行该驱动的自动化无标头安装，但它可运行任何内容。”  
  
攻击者触发该利用所需做的就是创建一个域名并托管三份文件，要运行的恶意payload、将属性 “SilentInstallRun” 属性设置为恶意二进制的 AsusSetup.ini 修改版本以及利用该属性运行payload 的 AsusSetup.exe。  
  
研究员在2025年4月8日负责任地披露该漏洞，华硕在5月9日修复，目前尚无证据表明这些漏洞已遭在野利用。华硕在一份安全通告中提到，“该更新中包含重要的安全更新，华硕强烈建议用户将 ASUS DriverHub 更新至最新版本。打开 ASUS DrvierHub 之后点击‘立即更新’按钮，即可访问最新软件更新。”  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[华硕修复严重的AMI 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522841&idx=1&sn=b39cd7520c5b0c63d3c0e807374feeb2&scene=21#wechat_redirect)  
  
  
[华硕：启用AiCloud 的路由器中存在严重的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522801&idx=1&sn=be29e21bdd328bab3ee1bbc42562d47e&scene=21#wechat_redirect)  
  
  
[华硕：严重的远程绕过漏洞影响7款路由器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519766&idx=1&sn=e5617e80059a29c20c16b011271e8511&scene=21#wechat_redirect)  
  
  
[华硕证实菲律宾员工数据被泄露在黑客论坛](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519060&idx=2&sn=6105a3152e4cf58dc7f6100cc53d066c&scene=21#wechat_redirect)  
  
  
[华硕路由器易遭多个RCE漏洞影响](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517570&idx=1&sn=34fd77e3506951e7f7fd62a7ab442b2c&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/05/asus-patches-driverhub-rce-flaws.html  
  
  
  
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
  
