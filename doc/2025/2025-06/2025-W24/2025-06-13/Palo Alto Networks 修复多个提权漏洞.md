> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523281&idx=2&sn=c4ed265127f77866bb9d4f397428f552

#  Palo Alto Networks 修复多个提权漏洞  
Ionut Arghire  代码卫士   2025-06-13 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**本周三，Palo Alto Networks公司发布了七份安全公告，详述了其产品中的多个漏洞以及对最近所发布 Chrome 修复方案的实现。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRV4TpHia5020fSlxqurOMJeyG88q4OfM02iapvB5icwRib9E4o3hWcRn2JrtJH6DDnGn3Wtu7SfTSgow/640?wx_fmt=png&from=appmsg "")  
  
  
在这些漏洞中，最严重的是位于 GlobalProtect for macOS 中的一个高危通配符中和不当漏洞，它可导致代码注入。该漏洞影响这款应用的日志收集特性，可被认证攻击者用于提权至 root。  
  
该公司还在产品中执行了11个Chrome 修复方案，以及影响 Prisma Access Browser 的内存中实现不当漏洞CVE-2025-4233的补丁。  
  
Palo Alto Networks 公司还修复了位于 PAN-OS 中的一个中危命令注入漏洞CVE-2025-4231，可导致攻击者认证为管理员，以root 权限执行操作。该公司解释称，“攻击者必须对管理web接口拥有网络访问权限，并获得成功认证才能利用该漏洞。”另外一个PAN-OS命令注入漏洞CVE-2025-4230可导致登录到管理员账户的攻击者利用CLI权限绕过系统限制并以root权限执行任意命令。该公司解释称，“将CLI访问权限限制到有限的管理员组，可将该漏洞带来的安全风险最小化。”  
  
Palo Alto Networks公司还修复了一个PAN-OS漏洞，它可导致用户拦截从防火墙发送的数据包，查看通过SD-WAN 接口发送的未加密数据。另外该公司还修复了位于 Cortex SDR Broker VM中的一个权限分配错误漏洞，可导致攻击者将权限提升至root。  
  
此外，该公司还修复了位于 GlobalProtect（Windows 和 macOS）“端点流量策略增强 (Endpoint Traffic Policy Enforcement)”特性中的一个访问控制不当漏洞，它可导致数据包处于未加密状态，并导致对网络具有物理访问权限的攻击者注入一个恶意设备并拦截这些数据包。  
  
Palo Alto Networks公司表示并未发现这些漏洞遭利用的证据。用户可参考该公司发布的安全公告，获取更多相关信息。  
  
  
****  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Palo Alto Networks 修复PAN-OS 中的认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522232&idx=2&sn=3bc7a4466c3c33ff643ca604524fa401&scene=21#wechat_redirect)  
  
  
[Palo Alto Networks 修复退市 Migration Tool中的高危漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522035&idx=2&sn=71c00b294647fadae4e56ffc500f1300&scene=21#wechat_redirect)  
  
  
[Palo Alto 修复已遭利用的严重PAN-OS DoS 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521932&idx=1&sn=518332fa38f3263ee23df7a70c1187d3&scene=21#wechat_redirect)  
  
  
[Palo Alto 防火墙 0day 由低级开发错误引发](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521617&idx=2&sn=0e9ac32a3223e727cd6cd99460e0387e&scene=21#wechat_redirect)  
  
  
[Palo Alto Networks：注意潜在的 PAN-OS RCE漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521440&idx=1&sn=3bf8ff26ce74c0c7fbfeb2701a773a5f&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/palo-alto-networks-patches-privilege-escalation-vulnerabilities/  
  
  
  
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
  
