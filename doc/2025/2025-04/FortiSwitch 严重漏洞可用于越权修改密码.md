#  FortiSwitch 严重漏洞可用于越权修改密码   
Ravie Lakshmanan  代码卫士   2025-04-09 17:49  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRLbRbjBCGBqeUgUkDYS8icy40gG4AgzGDzANnC3Fj9n1ZAd9J4gkachg27lCbxOVCwt7EsXgQIuRQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
**Fortinet  公司已发布安全更新，修复了影响FortiSwitch 的一个严重漏洞CVE-2024-48887，它可导致攻击者越权修改密码。**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRLbRbjBCGBqeUgUkDYS8icyAD1JQp3GIotdQibsOZrztLToj5oltK7r7UxccdF5C3fYo4SeibsTjSIw/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞的CVSS评分为9.3。Fortinet 公司发布安全公告提到，“FortiSwitch GUI 中存在一个未验证的密码修改漏洞[CWE-620]，可导致远程未认证攻击者通过一个特殊构造的请求修改管理员密码。”该漏洞影响如下版本：  
  
- FortiSwitch 7.6.0（升级至7.6.1或更高版本）  
  
- FortiSwitch 7.4.0 至 7.4.4（升级至7.4.5 或更高版本）  
  
- FortiSwitch 7.2.0 至7.2.8（升级至7.2.9或更高版本）  
  
- FortiSwitch 7.0.0 至 7.0.10（升级至7.0.11或更高版本）  
  
- FortiSwitch 6.4.0 至 6.4.14 （升级至6.4.15或更高版本）  
  
  
  
Fortinet 公司提到，该漏洞系内部发现，由 FortiSwitch web UI开发团队的成员 Daniel Rozeboom 发现。作为应变措施，Fortinet 公司建议禁用管理员界面的 HTTP/HTTPS 访问权限并仅限受信任主机访问该系统。  
  
虽然并未有证据表明该漏洞已遭利用，但一直以来影响 Fortinet 产品的安全漏洞就是攻击者的香饽饽，因此用户非常有必要迅速行动应用补丁。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet：注意这个认证绕过0day漏洞可用于劫持防火墙](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522078&idx=2&sn=a6a418ea6abb9635205b06203e061801&scene=21#wechat_redirect)  
  
  
[Fortinet：注意FortiWLM漏洞，黑客可获得管理员权限](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=1&sn=6aade83438190800942638166b046757&scene=21#wechat_redirect)  
  
  
[Fortinet 修复 FortiOS 中的代码执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519734&idx=2&sn=e2956d27d020b75520e84dc6e02b483a&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重的 FortiClientLinux 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519274&idx=1&sn=0db6fdb46bf03ada98af3901110ee37b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/04/google-releases-android-update-to-patch.html  
  
  
  
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
  
