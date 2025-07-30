#  Ivanti Workspace Control硬编码密钥漏洞暴露 SQL 凭据  
Sergiu Gatlan  代码卫士   2025-06-11 10:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Ivanti 公司发布安全更新，修复了位于该公司 Workspace Control (IWC) 解决方案中的三个高危硬编码密钥漏洞。**  
  
IWC 助力企业管理员管理桌面和应用程序，是操作系统和用户之间的中间角色并规范访问和工作空间配置。它基于策略和用户角色，对用户工作空间进行中心化控制并动态配置桌面、应用程序和用户设置。  
  
所有这三个漏洞均由使用硬编码的、无法更改的密钥引起，如遭成功利用和针对的账号，可导致提权和系统攻陷。  
  
其中两个漏洞（CVE-2025-5353和CVE-2025-22455）可导致本地认证攻击者在运行IWC 10.19.0.0.0和更早版本上解密存储型SQL凭据。第三个漏洞（CVE-2025-22463）可导致本地认证攻击者解密存储型环境密码。Ivanti 公司提到，“Ivanti已经为 Ivanti Workspace Control 发布更新，修复了三个高危漏洞。漏洞如遭成功利用可导致凭据攻陷后果。”  
  
  
**无遭在野活跃利用证据**  
  
  
  
  
幸运的是，Ivanti 尚未发现这三个漏洞在披露前遭在野利用的证据。  
  
Ivanti 公司此前曾宣布IWC将在2026年12月达到生命周期，之后将不再对其发布补丁和提供技术支持。5月份，该公司还修复了用于ITSM IT服务管理解决方案的 Neurons 中的一个严重认证绕过漏洞和被用于RCE攻击中的EPMM软件中的两个0day漏洞。  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Ivanti 修复已用于代码执行攻击中的两个 EPMM 0day 漏洞，与开源库有关](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523008&idx=1&sn=12a019a9d94970b49208b306f026f931&scene=21#wechat_redirect)  
  
  
[Ivanti 修复 Connect Secure & Policy Secure 中的三个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522224&idx=1&sn=671c73813c868c4819c48a9b54ab1b8c&scene=21#wechat_redirect)  
  
  
[Ivanti修复Endpoint Manager中的多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522089&idx=1&sn=a04239b89ce2032e8e28b49d05782135&scene=21#wechat_redirect)  
  
  
[Ivanti提醒注意 Connect Secure 产品中的新0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522025&idx=2&sn=f67e98879ae334210339981b77e939e9&scene=21#wechat_redirect)  
  
  
[Ivanti：注意这个CVSS 满分的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521758&idx=1&sn=d87a2de8e47def08cf6aca1b91b6e064&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/ivanti-workspace-control-hardcoded-key-flaws-expose-sql-credentials/  
  
  
  
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
  
