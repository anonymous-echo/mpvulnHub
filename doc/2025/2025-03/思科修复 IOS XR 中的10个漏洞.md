#  思科修复 IOS XR 中的10个漏洞   
Ionut Arghire  代码卫士   2025-03-17 19:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**上周，思科修复了IOS XR 中的10个漏洞，其中5个可用于引发拒绝服务 (DoS) 条件。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMS2aXNic9wicgVObDQAoga7YcpAfiaFevzCucSf2T3FPJTKtIdowvVrA5Dxg0fuecolHgmsrIUppYEFA/640?wx_fmt=gif&from=appmsg "")  
  
  
最严重的DoS 漏洞是高危的CVE-2025-20142和CVE-2025-20146，它们影响 Ipv4 访问控制列表 (ACL) 特性、服务策略质量 (QoS) 以及ASR 9000系列、ASR 9902和ASR 9903路由器的Layer 3多播特性。  
  
在应用了ACL 或QoS 策略的设备上对非法Ipv4 数据包的不正确处理，导致攻击者可发送构造的Ipv4 数据包并引发网络处理器错误、线卡异常或重置，导致DoS。  
  
思科还修复了位于 IKEv2 功能中的多个高危漏洞CVE-2025-20209以及IOS XR中对特定数据包处理不当的漏洞（CVE-2025-20141），均可导致DoS 条件。第五个DoS 漏洞是位于IOS XR 中BGP联合实现中的中危漏洞，它可遭远程利用且无需认证，在2024年9月公开报道。  
  
思科还修复了位于 IOS XR 的CLI 中的高危漏洞，它可导致攻击者以 root 身份执行任意命令，编号为CVE-2025-20138。该漏洞存在的原因是传递给 CLI 的用户参数的验证不足，导致攻击者可将构造的命令用作提示并提升权限。  
  
思科修复的另外两个高危 IOS XR 漏洞可导致具有 root 系统权限的攻击者绕过 Secure Boot 功能（CVE-2025-20143）或镜像签名验证（CVE-2025-20177）以及加载未认证的软件。思科还修复了因对数据包处理不正确引发的两个中危混合ACL绕过漏洞。  
  
思科表示尚未发现这些漏洞遭在野利用的迹象。用户可访问思科的安全公告页面或在该公司3月发布的 IOS XR 安全通告中获取更多信息。  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科：Webex 漏洞可导致凭据遭远程访问](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522410&idx=2&sn=0aef267bcd2c2f831a7dedbda98b4668&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭利用的 Windows 和思科漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522399&idx=1&sn=f2a16f697c5c7d7824f2f78d5b4b6148&scene=21#wechat_redirect)  
  
  
[思科ISE严重漏洞导致攻击者以root权限运行命令](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522190&idx=2&sn=9702cf83b7bdb3ee94d30829bea9f51b&scene=21#wechat_redirect)  
  
  
[思科提醒注意严重的DoS漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522160&idx=1&sn=1b0f6777dc7235311e5c6a6e6f764ee7&scene=21#wechat_redirect)  
  
  
[黑客泄露更多数据，思科证实属实](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521960&idx=2&sn=46eb22e98ed9cbd715a95b5188b6eac6&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/cisco-patches-10-vulnerabilities-in-ios-xr/  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
