#  开源项目 Parse Server 出现严重漏洞，影响苹果 Game Center   
Charlie Osborne  代码卫士   2022-06-23 18:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRTWwlpMCsdOcEFxPE5lpiac6CyicibeHLjIfr95bCib4XZibnsYEpGBWXwUJCS7CuImpmD7PezsibCiarIQ/640?wx_fmt=png "")  
  
开源项目 Parse Server 中存在一个漏洞，导致 Apple Game Center 出现认证绕过问题。  
  
  
  
Parse Server 是一款开源项目，向iOS、macOS、安卓和 tvOS 提供推送通知功能。该软件是一个后端系统，兼容任意能够运行 Node.js、Express web 应用框架以及独立于或与现有web应用运营的任何基础设施。  
  
6月17日发布的一份安全公告指出，Parse Server 遭遇 4.10.11/5.0.0/5.2.2中存在一个漏洞，可引发苹果Game Center 出现验证问题。苹果公司将 Game Center 称为“社交游戏网络”，该平台包括玩家明星榜以及实时的多用户游戏。  
  
  
**绕过认证**  
  
  
  
该漏洞的编号为CVE-2022-31083，CVSS评分为8.6，该漏洞发生的场景是苹果 Game Center的安全证书认证适配器无效。安全公告指出，“因此，通过制造某些苹果域名可访问的虚假证书，并将该URL提供给在authData对象中的证书，就可能绕过认证。”  
  
攻击复杂度不高且无需任何权限即可实施攻击。  
  
Parse Server 4.10.11/5.2.2 版本中已接收到修复方案。该软件的苹果Game Center认证适配器中已执行新的 rootCertificateUrl 属性，该适配器 “将该URL 带给苹果Game Center 认证证书的根证书中“。  
  
如开发人员尚未在认证系统中设立值，则该新的属性默认是苹果在用的根证书的URL。目前尚不存在应变措施。另外，该安全公告提到，在使用Parse Server Apple Game Center认证适配器的同时将根证书更新至最新状态也是苹果生态系统开发人员的职责。  
  
Game Center 将收到修订版本的控制面板，搭配iOS 16 中的朋友们的活动，并将在今年晚些时候发布。  
  
ESET公司的全球网络安全顾问 Jake Moore指出，“不当验证可导致攻击者绕过认证，使得服务器易受简单的远程攻击影响。苹果通常不会在安全特征上出错，但不设立认证要求是危险的而且很容易遭攻击。避免此类威胁的最佳方法是通过最新更新快速修复设备。“  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[奇安信开源软件供应链安全技术应用方案获2022数博会“新技术”奖](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512040&idx=1&sn=7cd8e2d87f73fab31fc52af90d624ccf&chksm=ea949e82dde317940861a08ced505fe54d9a3e5d934a86a09dc887e15908238e3a609484d10c&scene=21#wechat_redirect)  
  
  
[开源邮件平台Zimbra 出现新漏洞，用户登录凭据可被盗](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512333&idx=3&sn=8b2d3c40a59f28ad4ef19cca4e7de98c&chksm=ea948067dde3097194f650240489cdb2bfb2ee4a852e63ff960607da69af4ddc744d0a0e03d5&scene=21#wechat_redirect)  
  
  
[开源U-Boot 引导加载程序中存在两个未修复的严重0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512136&idx=1&sn=f1dff2c42ec635a5e317f36ae18cc7f3&chksm=ea948122dde30834305c643105f82ae611aa4a5aefda16ea90c19b366b76a46bf19dfeb70686&scene=21#wechat_redirect)  
  
  
[Kubernetes的开源GitOps 平台 Argo CD 中存在严重的提权漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511966&idx=2&sn=4d118084132be27daf3b30f265d2a43a&chksm=ea949ef4dde317e2288e7a4fe13293b18d1063fa90b1f31ab148d05aa255b0f652281b244c1b&scene=21#wechat_redirect)  
  
  
[开源的IT监控软件Icinga web 中存在两个漏洞，可被用于攻陷服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511800&idx=1&sn=0f335367280974447c6dea4d856bc39b&chksm=ea949f92dde31684607d46322cc43b6250fcfe1d328aee28eae6304ec2e5d82577b9209cd75e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/severe-parse-server-bug-impacts-apple-game-center  
  
  
题图：  
Pixabay License  
  
  
  
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
  
