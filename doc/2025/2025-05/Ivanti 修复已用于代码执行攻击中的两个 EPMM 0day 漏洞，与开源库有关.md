#  Ivanti 修复已用于代码执行攻击中的两个 EPMM 0day 漏洞，与开源库有关   
Sergiu Gatlan  代码卫士   2025-05-14 09:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**今天，Ivanti 公司督促客户修复 Ivanti Endpoint Manager Mobile (EPMM) 软件中的两个漏洞CVE-2025-4427和CVE-2025-4428，它们可组合用于获得远程代码执行权限。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS5h0SuuXM8RmRjHiaeibMd6clLBqCEkVcFPuRgGPcvAdaXib24ju6bqDxpq56cJgNA5dicat2KBbfUAQ/640?wx_fmt=png&from=appmsg "")  
  
  
Ivanti 公司提到，“Ivanti 已发布EPMM 更新，修复了一个中危和一个高危漏洞。组合利用这两个漏洞可导致未经认证的远程代码执行后果。我们发现数量非常有限的客户的解决方案在漏洞披露时已遭利用。”  
  
CVE-2025-4427时位于EPMM API组件中的一个认证绕过漏洞，可导致攻击者访问受影响设备上的受保护资源。CVE-2025-4428是一个远程代码执行漏洞，可导致攻击者通过恶意构造的API请求在目标系统上执行任意代码。  
  
Ivanti 公司表示，客户可安装EPMM 11.12.0.5、12.3.0.2、12.4.0.2或12.5.0.1版本缓解这两个0day漏洞。Ivanti 公司还提到，目前仍在调查这些攻击且无法提供妥协指标，客户应当联系支持团队获取进一步的指南。  
  
虽然Ivanti 公司表示这两个漏洞与EPMM 使用的两个开源库之间“存在关联”，但并未在公告中分享这两个库的名称。Ivanti 公司在另外一份安全公告中提到，“该漏洞仅影响本地部署的EPMM产品。它并不存在于适用于MDM的Ivanti EURONS、Sentry或其它产品中。”  
  
Shadowserver 威胁监控平台目前追踪到数百个被暴露到互联网中的 Ivanti EPMM 实例，它们多数位于德国（992个）和美国（418个）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMS5h0SuuXM8RmRjHiaeibMd6ciayRxztoGu1ld9UAP2VZoPv8dI1JvOJ4yW3D4Tyh8jicTh4MtoMJkfkg/640?wx_fmt=gif&from=appmsg "")  
  
**修复其它两个漏洞**  
  
  
今天，Ivanti 公司还发布另外一个安全更新，修复影响适用于ITSM IT服务管理解决方案的一个严重的认证绕过漏洞 (CVE-2025-22462)，它可导致未认证攻击者获得管理员访问权限。  
  
Ivanti 公司还提醒用户修复位于CSA中的一个默认凭据漏洞CVE-2025-22460，它可导致本地认证攻击者在易受攻击系统上提权。  
  
近年来，攻击者还利用其它多个漏洞攻击 Ivanti 公司的 VPN设备和ICS、IPS和ZTA网关。FBI 和 CISA 也在今年1月份联合发布一份公告称，威胁人员仍然在利用已存在多个月的CSA漏洞，攻陷易受攻击的网络。  
  
  
****  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Ivanti 修复 Connect Secure & Policy Secure 中的三个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522224&idx=1&sn=671c73813c868c4819c48a9b54ab1b8c&scene=21#wechat_redirect)  
  
  
[Ivanti修复Endpoint Manager中的多个严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522089&idx=1&sn=a04239b89ce2032e8e28b49d05782135&scene=21#wechat_redirect)  
  
  
[Ivanti提醒注意 Connect Secure 产品中的新0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522025&idx=2&sn=f67e98879ae334210339981b77e939e9&scene=21#wechat_redirect)  
  
  
[Ivanti：注意这个CVSS 满分的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521758&idx=1&sn=d87a2de8e47def08cf6aca1b91b6e064&scene=21#wechat_redirect)  
  
  
[Ivanti 中的3个0day已遭活跃利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521006&idx=2&sn=9a5993bb8ee14a8ab3071f40bb56c909&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/ivanti-fixes-epmm-zero-days-chained-in-co  
de-execution-attacks/  
  
  
  
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
  
