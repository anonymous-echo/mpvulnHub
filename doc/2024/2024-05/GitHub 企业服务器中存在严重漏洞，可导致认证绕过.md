#  GitHub 企业服务器中存在严重漏洞，可导致认证绕过   
THN  代码卫士   2024-05-22 17:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**GitHub 修复了位于GitHub 企业服务器 (GHES) 中的一个CVSS满分漏洞CVE-2024-4985，它可导致攻击者绕过认证防护措施。**  
  
CVE-2024-4985可使攻击者在无需提前认证的情况下，越权访问实例。该公司发布安全公告提到，“使用SAML单点登录认证的实例如具有可选的加密断言特性，则攻击者可伪造SAML响应以及/或者获得对具有管理员权限用户的访问权限。”  
  
GHES 是一款用于软件开发的自托管平台，可使组织机构通过使用 Git 版本控制存储并构建软件以及自动化部署管道。该漏洞影响 GHES 3.13.0之前的版本，已在版本3.9.15、3.10.12、3.11.10和3.12.4中修复。  
  
GitHub 提到，默认情况下加密断言并未启用，该缺陷并不影响未使用 SAML 单点登录或使用SAML单点登录认证但未配备加密断言的实例。加密断言可使站点管理员通过SAML单点登录的方式，加密 SAML 身份提供商在认证流程中发送的信息，改进 GHES 实例的安全性。建议使用易受攻击 GHES 版本的组织机构更新至最新版本，以免遭潜在安全威胁影响。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitHub 评论被滥用于推送恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519338&idx=3&sn=ce709d5220bb6c2f682b40e739ddb45a&chksm=ea94bd00dde3341689317ffd9ae079e27052fd9394be372945e3ac51a63d809ddd7ba6f7ee53&scene=21#wechat_redirect)  
  
  
[供应链攻击滥用 GitHub 特性传播恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519269&idx=2&sn=d6c911a2eb50fa5c85016bfc6439be5a&chksm=ea94bd4fdde3345906eee3ee7e47e08bfd5fa5e98365e6741efdc8cffeef3e77b4f697c09d28&scene=21#wechat_redirect)  
  
  
[QNAP提醒注意NAS设备中严重的认证绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519033&idx=2&sn=59f095fb0e0636ab2257aaf9cc7d7e27&chksm=ea94ba53dde333458f33894831a44c39ac69f925de1b9e7262ba526c9c4ebe0f113e84a4f2e5&scene=21#wechat_redirect)  
  
  
[速修复！Fortra GoAnywhere MFT 中存在严重的认证绕过漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518740&idx=1&sn=f97575a3c85c3e1d61c6ede1e31c0f1d&chksm=ea94bb7edde33268c42b5b9a74eb3ee30ceb5c34a906ff95500378175e985f1b8e0554fbcf3d&scene=21#wechat_redirect)  
  
  
[VMware 披露严重的VCD Appliance认证绕过漏洞，无补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518139&idx=2&sn=4951a6280d077d8cd04309f6629182e3&chksm=ea94b6d1dde33fc71b53f7879454b257d922f83689acde6d310a195b1857f38098ca7685fcca&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/05/critical-github-enterprise-server-flaw.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
