#  Fortinet 提醒注意严重的FortiSIEM命令注入漏洞   
Bill Toulas  代码卫士   2023-11-17 17:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Fortinet 提醒客户称，FortiSIEM 报送服务器中存在一个严重的 OS 命令注入漏洞，远程未认证攻击者可通过特殊构造的 API 请求执行命令。**  
  
  
FortiSIEM（安全信息和事件管理）是一款综合的网络安全解决方案，为组织机构提供关于安全态势的增强型可见性和控制。该解决方案用于规模不一的组织机构中，涉及医疗、金融、零售、电商、政府和公共行业等。  
  
  
**0****1**  
  
**另外一个OS命令注入漏洞的变体**  
  
  
  
该漏洞的编号是CVE-2023-36553，是 Fortinet 产品安全团队在本周早些时候发现的，并将其严重性评分评级为 9.3 分。然而，美国国家标准与技术局 (NIST) 将给出的评分是9.8分。Fortinet 公司提到，它可导致远程未认证攻击者通过构造的API请求执行越权命令。  
  
研究人员提到，CVE-2023-36553是10月初修复的严重漏洞CVE-2023-34992的变体。程序将API请求传递给OS作为被执行的命令，导致越权数据访问、修改或删除等危险场景。  
  
受影响版本包括 FortiSIEM 4.7 至5.4版本。Fortinet 公司督促系统管理员升级至版本 6.4.3、6.5.2、6.6.4、6.7.6、7.0.1或7.1.0和后续版本。  
  
  
**0****2**  
  
**常遭攻击**  
  
  
  
Fortinet 公司的产品包括防火墙、终端安全和入侵检测系统，它们常常是国家黑客组织入侵组织机构网络的入口点。此前其产品曾遭多次利用，而且在一些情况下 Fortinet 公司产品中的 0day 漏洞被用于攻陷政府机构网络。  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Fortinet 修复影响多款产品中的高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517693&idx=2&sn=ee2f37800cd4fde8239f203b3abcd5d3&chksm=ea94b497dde33d818a22818925aba4c372988566412b75f81318126b467d62a54093436d6e12&scene=21#wechat_redirect)  
  
  
[Fortinet：速修复 FortiOS、FortiProxy 设备中的严重RCE漏洞！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517034&idx=2&sn=0e6034be825eac879386635841578fa0&chksm=ea94b200dde33b16e5b00a74e6327aca06b3192a6c9501d14cc86edab7c248c3044a44ff1a9c&scene=21#wechat_redirect)  
  
  
[Fortinet 修复严重的 FortiNAC 远程命令执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516818&idx=3&sn=7524bc2288375bbf06f9574e73e15a00&chksm=ea94b3f8dde33aeeeb1313ae4cb6608ffa6876baa1ba49cbdac2b97cf5307198a79fd41eed8b&scene=21#wechat_redirect)  
  
  
[Fortinet 修复 Fortigate SSL-VPN 设备中严重的 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516712&idx=1&sn=db056d3f152e8f52867cc5021679e6f1&chksm=ea94b342dde33a543f8d7daaae604ffb6f0a65f865bf3fd926dfee86ad48be7d6460b9107d7d&scene=21#wechat_redirect)  
  
  
[Fortinet 修复FortiADC 和 FortiOS 中的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516406&idx=3&sn=f6d52c7913cb9a7127079a424f287d22&chksm=ea94b19cdde3388a41d9382c14e8649d4db7f27382de8b638a8c2430d9fb7a6e3125a60ceed6&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/fortinet-warns-of-critical-command-injection-bug-in-fortisiem/  
  
  
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
  
