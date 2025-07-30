#  罗克韦尔ThinManager 多个漏洞可导致工业HMI 易遭攻击   
Eduard Kovacs  代码卫士   2023-08-25 17:45  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**研究人员在罗克韦尔自动化的 ThinManager ThinServer 产品中发现了多个漏洞，可用于攻击工业控制系统 (ICS)。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS8Ds6nFbo9GlibvnRLWiareCKC0oLaNRsV0tGHjdiaRviaSahdsfdpCTrZr9TOp15nRtzOMzrFY6iaxiaQ/640?wx_fmt=png "")  
  
  
Tenable 公司的研究人员在罗克韦尔提供的瘦客户端和 RDP 服务器管理软件 ThinManager ThinServer 中发现了一个严重漏洞和两个高危漏洞，CVE-2023-2914、CVE-2023-2915和CVE-2023-2917。  
  
这些漏洞被描述为输入验证不当问题，可导致整数溢出或路径遍历后果。远程攻击者无需事先认证即可通过发送特殊构造的同步协议信息的方式，利用这些漏洞。利用这些漏洞可引发拒绝服务条件、以系统权限删除任意文件并将任意文件上传到安装了 ThinServer.exe 的驱动上的任意文件夹中。  
  
研究人员在5月份将这些漏洞告知厂商，并在补丁发布日即8月17日发布了技术详情。Tenable 公司还开发了PoC exp 但并未公开。  
  
Tenable 公司表示，利用的唯一条件是访问托管易受攻击服务器的网络。如果服务器联网且暴露到 web，则可直接从互联网实施利用，但这并非厂商推荐的最佳实践。  
  
Tenable 公司提到，“成功利用可使攻击者完全控制 ThinServer。该访问权限的真实影响取决于环境、服务器配置和服务器所配置和所访问的内容类型。”该公司注意到，这款产品一般用于控制和监控工业设备的人机接口。该公司提到，“攻击者将能够获得这些HMI 的访问权限，也可从服务器跳转攻击位于网络上的其它资产。”  
  
本周，CISA 也发布了安全公告将漏洞告知相关组织机构。  
  
罗克韦尔自动化公司产品中的漏洞可遭攻击者利用。最近，一个未具名APT组织利用的就是ControlLogix 漏洞。该漏洞可用于干扰或破坏关键基础设施组织机构。罗克韦尔发现了“新的exp 能力”，但并未发现遭在野利用的迹象。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[罗克韦尔提醒关基或遭APT组织RCE漏洞利用攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517076&idx=1&sn=5d64e3975416d9a2acd6b0ae94ceec96&chksm=ea94b2fedde33be8db007deb0d5e30088fbd4d8a0748739733378f6ba498f8ec8e4997102ba5&scene=21#wechat_redirect)  
  
  
[堪比“震网”：罗克韦尔PLC严重漏洞可导致攻击者在系统中植入恶意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511227&idx=1&sn=d28db703c4a8b363e328e4d7bd31acb6&chksm=ea949dd1dde314c7695fa5ecca6c16c0f8905de7f968f34a026fb212d3db07b9891b7995210f&scene=21#wechat_redirect)  
  
  
[利用罗克韦尔控制器缺陷将用户重定向至恶意站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489812&idx=3&sn=b2065ad314087c8f22c89c1057ae06d1&chksm=ea97287edde0a168d38b8525c6f216b2e634bbc1f2a5349901c75c519bb7b0966420b4a598ea&scene=21#wechat_redirect)  
  
  
[罗克韦尔控制器易受 DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488700&idx=3&sn=131385d54e581f0ac35918fdc466df20&chksm=ea9725d6dde0acc01365f9cc2232e55e3641f8e8658380abce1e69886741ffa3c22d53458b82&scene=21#wechat_redirect)  
  
  
[罗克韦尔修复模拟软件和许可工具中的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487110&idx=5&sn=0853833ed4c69b592b3a9504770c38bd&chksm=ea973fecdde0b6fad8844388899ba16ad16fc7741133b44c184804f8b2556abf41a8789dc9a3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/rockwell-thinmanager-vulnerabilities-could-expose-industrial-hmis-to-attacks/  
  
  
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
  
