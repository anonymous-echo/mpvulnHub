#  这个Sonos One 扬声器漏洞价值10.5万美元   
Ravie Lakshmanan  代码卫士   2023-05-31 17:24  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**上周，ZDI发布报告指出，Sonos One 无线扬声器中存在多个漏洞，可导致信息泄露和远程代码执行后果。**  
  
  
  
  
这些漏洞已经由Qrious Secure、STAR Labs 和 DEVCORE 三家公司的研究员在去年的多伦多 Pwn2Own 大赛上演示，这三家公司为此获得10.5万美元的现金奖励。  
  
这四个漏洞影响 Sonos One Speaker 70.3-35220，它们是：  
  
- CVE-2023-27352和CVE-2023-27355（CVSS评分8.8）：它们是未认证缺陷，可导致网络邻近攻击者在受影响安装程序上执行任意代码。  
  
- CVE-2023-27353和CVE-2023-27354（CVSS评分6.5）：它们是未认证缺陷，可导致网络邻近攻击者在受影响安装程序上泄漏敏感信息。  
  
  
  
CVE-2023-27352是在处理 SMB 目录查询命令时造成的，而CVE-2023-27355位于 MPEG-TS解析器中。成功利用这两个漏洞，均可导致攻击者在 root 用户上下文中执行任意代码。  
  
这两个信息泄露漏洞可与系统中的其它缺陷分别组合利用，以提升后的权限实现代码执行。  
  
在2022年12月29日收到漏洞通知后，Sonos 公司在 Sonos S2和S1版本15.1和11.71中修复了这些漏洞。建议用户尽快应用这些补丁，缓解潜在风险。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[研究人员发现Google 智能扬声器中的多个漏洞，获奖超10万美元](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515192&idx=2&sn=272bc0a3af1895e35d8757fc824d54e7&chksm=ea948d52dde3044428c3a85f3626292aa92baae3cad83b4c5ec41f5fe18285b316d2ca225fa6&scene=21#wechat_redirect)  
  
  
[用 Sonos 设备边听音乐边工作？小心泄露个人和公司信息](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486132&idx=2&sn=7c651fe209afd43fbf351b9d90ef6c6b&chksm=ea973bdedde0b2c89b531b81423afcbb5afd3e782007068650d1365734d9639cc8f8ec1aa59f&scene=21#wechat_redirect)  
  
  
[Nexx 智能设备存在多个漏洞可使黑客打开车库门等，无修复方案](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516175&idx=2&sn=622c1e525eac66ff89956cf0d9c7c94b&chksm=ea94b165dde33873d49fb73b3c492d7b57426e571702dc507fa765696fae2dc5c921f62762a4&scene=21#wechat_redirect)  
  
  
[Anker Eufy 智能设备系统易受严重的RCE漏洞影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512404&idx=2&sn=c658bb128dac22af8e2041f4d86d9c98&chksm=ea94803edde309286702f0b3b4638f0e87262ccd067fca6402a3f21d7cd880e36026452daa2e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/05/hackers-win-105000-for-reporting.html  
  
  
题图：Pexels License  
  
  
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
  
