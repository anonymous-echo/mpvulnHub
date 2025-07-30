#  Fortinet 修复多个路径遍历漏洞   
Adam Bannister  代码卫士   2022-07-08 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Fortinet 修复了影响多款端点安全产品的多个漏洞。**  
  
  
Fortinet 为全球提供超过三分之一的防火墙和统一威胁管理产品，它在7月5日发布了大量防火墙和软件更新。  
  
Fortinet 修复的漏洞包括位于 FortiDeceptor 管理接口中的多个相关路径遍历漏洞（CVE-2022-30302），如遭利用“可导致远程认证攻击者通过特殊构造的web请求从底层文件系统中检索并删除任意文件”。同样地，攻击者可通过FortiESNAC 服务named 管道中的路径遍历漏洞，在端点防护和VPN产品 FortiClient 的Windows 版本中实现权限提升。  
  
FortiNAC 网络访问控制解决方案也受“配置文件中空密码漏洞”的影响，认证攻击者可利用该漏洞通过命令行接口 (CLI) 访问MySQL 数据库 (CVE-2022-26117)。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQAJnxlgw3qGI773nY4RzUhRmJFOnFAQDCDzcaaQ5jtURUHC9r00gUFeCltj5gToxSl6yBZh6cwow/640?wx_fmt=gif "")  
  
**其它漏洞**  
  
  
  
其它高危娄冬冬哥位于安全事件分析工具 FortiAnalyzer、FortiManager 网络管理设备、FortiOS 操作系统和 FortiProxy web 代理中，“可导致权限攻击者通过特殊构造的 CLI ‘执行还原图像’ 和 ‘执行证书远程’ TFTP 协议操作，执行任意代码或命令”（CVE-2021-43072）。  
  
中危漏洞包括位于 FortiADC 应用交付控制器中的SQL 漏洞（CVE-2022-26120）和位于 FortiAnalyzer 和 FortiManager 中的OS 命令注入漏洞 (CVE-2022-27483)。  
  
此外，Fortinet 还修复了位于FortiEDR 端点安全解决方案中的XSS漏洞（CVE-2022-29057）、FortiManager 和 FortiAnalyzer 中的权限提升漏洞（CVE-2022-26118）以及影响 FortiOS 和 FortiProxy 的诊断性CLI 命令中的栈缓冲区溢出漏洞（CVE-2022-44170）。  
  
第六个和第七个中危漏洞是位于 dhcpd 守护进程中的整数溢出漏洞，影响 FortiOS、FortiProxy、FortiSwitch 以太网交换机、FortiRecoder 视频监控系统和 FortiVoiceEnterprise 通信系统（CVE-2021-42755）。  
  
最后，Fortinet 还修复了影响 FortiOS 的一个低危XSS漏洞（CVE-2022-23438）。  
  
  
****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[黑客利用老旧安全缺陷攻破数万未打补丁的 Fortinet VPN 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507850&idx=3&sn=2ef6c8e24754e7f6c84db9a5eebc9841&chksm=ea94eee0dde367f6cc369d9e7480161d5b32ed4fd175215145390fd16c0d196639a57d4f0bbe&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重漏洞，可导致未认证黑客以最高权限执行任意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506504&idx=2&sn=35c13960da760d7876e70f5121125275&chksm=ea94eb22dde36234754f1f38fe2d445936f50fb540211ea13e2516f5344a7132ca0857e97f94&scene=21#wechat_redirect)  
  
  
[Fortinet 防火墙受高危漏洞影响，可遭远程攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506050&idx=3&sn=5190aa1ab97106f1933f5b6bed5612c6&chksm=ea94e9e8dde360fe6594ce06673ef43141a38022b2bb95ce168634ffbac685503db7be04db69&scene=21#wechat_redirect)  
  
  
[美国：APT 组织正在利用 Fortinet FortiOS 发动攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247503245&idx=3&sn=856f262b27f3310cf14d0eaafade5f5c&chksm=ea94fce7dde375f100cb59392a9ae514a6174d710990f6583117019c4df9a7761da88d23d49c&scene=21#wechat_redirect)  
  
  
[Fortinet 修复SSL VPN 和 Web 防火墙中的严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501177&idx=2&sn=c38d5f5ad1fa2859f2ee4a4de04a5681&chksm=ea94f413dde37d05d182929d2ce2949437eb86d96443c890037b7e30897fd2b0221094adbef1&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/fortinet-patch-batch-remedies-multiple-path-traversal-vulnerabilities  
  
  
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
