#  CrushFTP 提醒用户立即修复已遭利用的 0day 漏洞   
Sergiu Gatlan  代码卫士   2024-04-23 15:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**近日，CrushFTP 公司在一份非公开备忘录中提醒客户称，今天发布的新版本中修复了一个已遭活跃利用的 0day 漏洞，它可导致未认证攻击者逃逸用户的虚拟文件系统并下载系统文件，督促用户立即修复服务器。**  
  
  
  
不过，在主 CrushFTP 实例前使用DMZ（非军事区）周边网络的用户不受该攻击影响。该公司在邮件中提醒用户称，“请立即采取措施尽快打补丁。今天（2024年4月19日）报送的漏洞，我们立即将其修复。该漏洞在野存在。该漏洞的底线是任何通过 WebInterface的未认证或认证用户可检索并非其虚拟文件系统组成部分的系统文件，从而导致提权等后果。”  
  
该公司还提醒称，如用户的服务器仍然运行 CrushFTP v9，则应立即升级至v11或通过主板更新实例。CrushFTP 公司提醒称，“如果遇到一些功能问题或回归，则需要简单回滚。立即更新。”  
  
该漏洞由 Airbus CERT 的研究员 Simon Garrelou 报送，目前已在 CrushFTP 10.7.1和11.1.0中修复。从Shodan 搜索结果可知，至少有2700个 CrushFTP 实例的 web 接口被暴露到网络，尽管现在无法判断尚未打补丁的数量。  
  
  
**已在针对性攻击中被利用**  
  
  
网络安全公司 CrowdStrike 也在情报报告中确认了该漏洞（尚无CVE编号）的存在，并进一步提供了该攻击者的战术、技术和目标。  
  
该公司表示，Falcon OverWatch 和 Falcon Intelligence 团队发现CrushFTP 0day 漏洞被用于目标攻击中。威胁行动者们正在攻击多家美国组织机构中的 CrushFTP 服务器，并有证据表明为情报收集活动服务，目的可能是出于政治目标。该公司指出，“Falcon OverWatch 和 Falcon Intelligence 已发现该利用被用于在野针对性攻击中。CrushFTP 用户应该持续追踪厂商网站，获得最新指南并安排修复优先级。”  
  
去年11月，CrushFTP 提醒用户修复一个严重的RCE漏洞 (CVE-2024-43177)。该漏洞由 Converge 公司的安全研究员报送，后者还发布了 PoC 代码。****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Telegram 修复Windows 版中的0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519289&idx=2&sn=4c3fb5e7519056c3adfbd18c7a6561d3&chksm=ea94bd53dde3344539968f93bb42b9cdb70baafffb79a18115ec887be44e431cd86921fbf01b&scene=21#wechat_redirect)  
  
  
[Palo Alto：注意！PAN-OS 防火墙 0day 漏洞已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519289&idx=1&sn=86e226003b5da9dd0d6867f4b45fcb1a&chksm=ea94bd53dde33445851c3ec7ca670a0d3c51235d027e8d130593cdc9eabd3a33d9758580655a&scene=21#wechat_redirect)  
  
  
[微软4月补丁星期二值得关注的漏洞：4个0day及更多](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519261&idx=1&sn=1f669e17acccbb5f3a974c466686d164&chksm=ea94bd77dde334619c916fa753497a102ad012bb069cba0cc174d147abf2488f2e649f7953f7&scene=21#wechat_redirect)  
  
  
[Crowdfense 出价3000万美元收购安卓、iOS和浏览器0day利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519250&idx=1&sn=a9eb759176bc25d080dd038567016edc&chksm=ea94bd78dde3346e8571088ffb3e1104df63785be22cebfc4b338fab213de9a5a83aec96d089&scene=21#wechat_redirect)  
  
  
[谷歌修复遭取证公司利用的两个 Pixel 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519231&idx=1&sn=5f9f5009dffb1ec140664df249e99fae&chksm=ea94ba95dde33383baddf488f4094e6fa0cd272867dd83693a008407c6112765694a7f8ef1d6&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/crushftp-warns-users-to-patch-exploited-zero-day-immediately/  
  
  
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
  
