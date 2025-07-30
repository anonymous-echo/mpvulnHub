#  谷歌紧急修复已遭利用的Chrome 0day   
Bill Toulas  代码卫士   2022-11-28 17:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRFJIlJKBHmHnP9tG2Ze4hSjxtNfiaXiaB5Wj8a0k1xiaszLWNo3OINdX8HlyAlEw7YW2ZDV3IHVmMIQ/640?wx_fmt=gif "")  
  
**谷歌紧急修复2022年以来的第8个Chrome 0day (CVE-2022-4135)。**  
  
  
该漏洞是位于GPU中的一个堆缓冲溢出漏洞，是由谷歌威胁分析团队研究员Clement Lecigne在2022年11月22日发现的。谷歌更新指出，“谷歌已在野发现CVE-2022-4135的exploit。”  
  
谷歌并未发布相关详情，以便用户有足够时间应用安全更新。谷歌指出，“漏洞详情可能会在大部分用户应用修复方案后发布。如果该漏洞也存在于其它项目依赖的第三方库中但并未被修复，则详情也不会发布。”  
  
一般来说，堆缓冲区溢出漏洞是一个内存漏洞，可导致在未经检查的情况下，数据被写入被禁止的（通常是邻近的）位置。攻击者可利用堆缓冲区溢出漏洞覆写应用的内存，以操纵其执行路径，从而导致信息访问不受限制或任意代码执行后果。  
  
建议Windows 系统的 Chrome 用户更新至版本107.0.5304.121/122，Mac 和 Linux 用户更新至版本107.0.5304.122。  
  
  
**2022年修复的第8个0day**  
  
  
  
  
  
Chrome 版本107.0.5304.121/122修复了今年以来的第8个已遭利用0day，说明攻击者对广泛使用的浏览器兴趣非常高。  
  
此前修复的7个Chrome 0day分别是：CVE-2022-3723、CVE-2022-3705、CVE-2022-2856、CVE-2022-2294、CVE-2022-1364、CVE-2022-1096、CVE-2022-0609。  
  
这些漏洞通常被黑客用于高针对性攻击活动中。  
  
强烈建议所有Chrome 用户尽快将Chrome浏览器更新至最新版本。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软补丁星期二修复6个已遭利用的0day和ProxyNotShell 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514441&idx=1&sn=a687462eb551d63fbb672860005a9ac6&chksm=ea948823dde30135c59d68023becb7756a805bf09a7b4194b440161543de8d40661c97ee9531&scene=21#wechat_redirect)  
  
  
[谷歌Chrome紧急修复已遭利用的 V8类型混淆0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514366&idx=2&sn=20f6b5becbcb5bccca826614a71fbb52&chksm=ea948994dde30082201cbb54dca1eb125118589807350c3075bde26c8dc15963db2ff45ae2b0&scene=21#wechat_redirect)  
  
  
[苹果修复已遭利用的第9枚0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514319&idx=1&sn=10f6c5afa8be65b7ccac62c9ab73645c&chksm=ea9489a5dde300b312a93ec52a321f835baed001465326883dd6cdbbe70fecd5b94b1b8000c7&scene=21#wechat_redirect)  
  
  
[微软证实称两个Exchange 0day 正遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514120&idx=1&sn=875f2a8038dd18f4393f68e4958721d8&chksm=ea948962dde3007476979db37549927911d0a40f66cd92734aac2576932e65c02e814b4d2292&scene=21#wechat_redirect)  
  
  
[速修复！Sophos 防火墙中的RCE 0day已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514074&idx=1&sn=849d683aa4c7d4ef90f9f8b7e1c2da9c&chksm=ea9486b0dde30fa63d6a04185ca12a12f4d497590f1bfaca5758906648d912976659d1b9d701&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/google-pushes-emergency-chrome-update-to-fix-8th-zero-day-in-2022/  
  
  
题图：  
Pixabay License  
  
‍  
  
  
  
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
  
