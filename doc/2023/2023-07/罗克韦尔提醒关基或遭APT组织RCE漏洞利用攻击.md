#  罗克韦尔提醒关基或遭APT组织RCE漏洞利用攻击   
Sergiu Gatlan  代码卫士   2023-07-17 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**罗克韦尔自动化公司表示，与某未具名APT组织相关联的一个新的RCE利用可用于攻击未修复的 ControlLogix 通信模块中，而该模块常用于制造、电力、油气和液化天然气行业中。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQgywkCdhtMO7yOSfwckoSuU0ibBib3b0HPAhQZDxPkcwfibM9eY6wkicLvynibya1XYyBxDiafFLspRxqA/640?wx_fmt=gif "")  
  
  
罗克韦尔自动化公司与CISA联合分析了该利用，但尚未透露如何获得该利用。该公司在一份安全公告中指出，“罗克韦尔自动化公司与美国政府一期，分析了APT威胁者的一种新型利用能力，该能力影响某些通信模块。我们尚未看到利用该能力的情况，受害者的相关信息尚不清楚。”  
  
该漏洞 (CVE-2023-3595) 是由界外读弱点引发的，可导致攻击者通过恶意构造的CIP消息获得远程代码执行能力或者触发拒绝服务状态。利用成功后，恶意人员还可操纵该模块的固件、擦除模块内存、修改流入或流出该模块的数据、设置持久性控制并可能影响所支持的工业进程。该公司提到，“安装易受攻击的模块后，这可导致破坏性操作，如对关键基础设施造成破坏等。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQgywkCdhtMO7yOSfwckoSuVhmFh72Yo5ezYfbQc32pvgPudCyiaYkPHs0LiaP5bT48pVddCovrwLfw/640?wx_fmt=gif "")  
  
**尽快修复所有受影响产品**  
  
  
  
罗克韦尔公司强烈建议为所有受影响产品（包括不受支持的产品）应用安全补丁，同时还提供了检测规则，帮助防御人员检测网络中的利用尝试。  
  
CISA 发布安全公告，提醒罗克韦尔客户修复该严重的 RCE 漏洞，阻止潜在攻击。  
  
Dragos 公司也分析了该 RCE 利用并提到，“利用前了解由 APT 所拥有的漏洞对于关键工业部门的主动性防御而言是一种罕见的机会。我们了解到未知 APT 阻止所有利用，尚未看到或发现任何在野利用。”该公司表示，CVE-2023-2595所获得的权限级别类似于俄罗斯威胁组织 XENOTIME 所利用的0day，后者利用 TRISIS（即 TRITON）破坏性恶意软件在2017年攻击施耐德电气公司的 Triconex ICS 设备。  
  
罗克韦尔公司也提醒称，“之前的威胁行动者活动涉及工业系统，说明这些能力很有可能是为了攻击关键基础设施，该受害者可能包括国际客户。威胁活动可能会发生变化，使用受影响产品的客户如遭暴露，则可能面临严重风险。”  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[堪比“震网”：罗克韦尔PLC严重漏洞可导致攻击者在系统中植入恶意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511227&idx=1&sn=d28db703c4a8b363e328e4d7bd31acb6&chksm=ea949dd1dde314c7695fa5ecca6c16c0f8905de7f968f34a026fb212d3db07b9891b7995210f&scene=21#wechat_redirect)  
  
  
[利用罗克韦尔控制器缺陷将用户重定向至恶意站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489812&idx=3&sn=b2065ad314087c8f22c89c1057ae06d1&chksm=ea97287edde0a168d38b8525c6f216b2e634bbc1f2a5349901c75c519bb7b0966420b4a598ea&scene=21#wechat_redirect)  
  
  
[罗克韦尔控制器易受 DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488700&idx=3&sn=131385d54e581f0ac35918fdc466df20&chksm=ea9725d6dde0acc01365f9cc2232e55e3641f8e8658380abce1e69886741ffa3c22d53458b82&scene=21#wechat_redirect)  
  
  
[罗克韦尔修复模拟软件和许可工具中的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247487110&idx=5&sn=0853833ed4c69b592b3a9504770c38bd&chksm=ea973fecdde0b6fad8844388899ba16ad16fc7741133b44c184804f8b2556abf41a8789dc9a3&scene=21#wechat_redirect)  
  
  
[思科 IOS 缺陷问题导致罗克韦尔自动化交换机易遭攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486915&idx=5&sn=22161addb0e974fb3be0242972629852&chksm=ea973ca9dde0b5bf9b707c48fd7866c20754251effac6289b2f83dc80540f1ab7b8ce096f27e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/rockwell-warns-of-new-apt-rce-exploit-targeting-critical-infrastructure/  
  
  
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
  
