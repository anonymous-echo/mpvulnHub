#  CISA：这个严重的 Ivanti vTM 漏洞已遭利用   
THN  代码卫士   2024-09-25 17:28  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMR60Qt6a0aJL6OFIF2x4Hb68zq50kSUiaOGyict2L9J1SMcBZw2qY8tVVML807rFxTs9AebbLDKuOBw/640?wx_fmt=gif&from=appmsg "")  
  
**美国网络安全和基础设施局 (CISA) 周二将影响 Ivanti Virtual Traffic Manager (vTM) 的一个严重漏洞纳入必修清单 (KEV)。**  
  
  
该漏洞是CVE-2024-7593，CVSS评分9.8，可被远程未认证攻击者绕过管理面板认证并创建恶意管理员用户。CISA提到，“Ivanti Virtual Traffic Manager 中存在一个认证绕过漏洞，可导致远程未认证攻击者创建一个所选的管理员账户。”该漏洞已于8月份在 vTM 22.2R1、22.3R3、22.5R2、22.6R2和22.7R2修复。  
  
CISA 并未透露该漏洞如何被用于真实攻击中以及攻击者的身份，但Ivanti公司此前曾表示已出现该漏洞的公开 PoC。鉴于最新进展情况，CISA要求联邦民用行政部门在2024年10月15日前修复。近几个月来，影响 Ivanti 设备的多个漏洞已遭在野利用，如CVE-2024-8190和CVE-2024-8963。Ivanti 公司证实称，已发现”数量有限的客户”遭这两个漏洞利用攻击。  
  
Censys 共享的数据表明，截止到2024年9月23日，已有2017台 Ivanti Cloud Service Appliance (CSA) 实例被暴露在网络，其中多数位于美国。目前尚不清楚有多少台是真实可疑的。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[CISA：不安全软件的生产者就是恶棍的帮凶](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520903&idx=1&sn=768f0341b9f1b3432c6427db84765ddb&chksm=ea94a3eddde32afbb676980f5d5120ed1fb787b9ddb9cfc6e142a34bcdfca2f4780440027c02&scene=21#wechat_redirect)  
  
  
[CISA 提醒注意已遭利用的 Apache HugeGraph-Server 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520886&idx=1&sn=d50fe47ebc8b4ad640aab8d8ead453e4&chksm=ea94a31cdde32a0a3cb660901fbb4949d1bd11b55a7718fcf71f3c28cf274e27bc3e091b0c27&scene=21#wechat_redirect)  
  
  
[CISA 和 Ivanti： Cloud Services Appliance 高危漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520811&idx=1&sn=890fffef04e0244ca4a0fe359dfb3886&chksm=ea94a341dde32a57534c153b9526fd132574d3fa54a5c70c2bf6fe73dcf1c38e1c35c88ce3d1&scene=21#wechat_redirect)  
  
  
[Ivanti 修复Endpoint Management 软件中的严重RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520759&idx=2&sn=1fc5e0f7a15b2f6ee85191294e7148e0&chksm=ea94a09ddde3298b03f1d93d760c4ebe1bbf0831c2823c5d15bdc98a012ee7662c48075afa5d&scene=21#wechat_redirect)  
  
  
[Ivanti：注意！Avalanche MDM 解决方案中存在多个严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519303&idx=2&sn=e86decfa003bf7ebcb19d43552440c7f&chksm=ea94bd2ddde3343b1eba25473eb57c432ce40d7ded22623619060fbc6c299c461dc0087f1d1b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2024/09/cisa-flags-critical-ivanti-vtm.html  
  
  
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
  
