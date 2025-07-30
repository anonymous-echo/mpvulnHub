#  速修复！VM2 库中又出现严重的沙箱逃逸漏洞   
Bill Toulas  代码卫士   2023-04-19 18:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**研究人员发现了另外一个沙箱逃逸漏洞，可被用于在运行 VM2 沙箱上运行的主机上执行不安全的代码。**  
  
VM2 是大量软件工具使用的特定 JavaScript 沙箱，用于在隔离环境中运行并测试不受信任的代码，阻止代码访问主机的系统资源或外部数据。VM2 库常见于 IDEs、代码编辑器、安全工具和多种渗透测试框架中，在 NPM 包仓库中每个月的下载量达到数百万次。  
  
两周来，多名安全研究员披露了多个严重的沙箱逃逸漏洞，使得攻击者能够不受沙箱环境的限制，运行恶意代码。第一个沙箱逃逸漏洞是由 Seongil Wi 在两周前发现的 CVE-2023-29017，最新的两个是由 SeungHyun Lee 发现的，编号为CVE-2023-29199和CVE-2023-30547。Oxeye 公司的研究员在2022年10月发现了另外一个沙箱逃逸漏洞CVE-2022-36067。  
  
  
**沙箱逃逸缺陷**  
  
  
CVE-2023-30547 的CVSS评分为9.8，是一个异常处理漏洞，可导致攻击者在 handleException() 中引发未清理的主机异常。  
  
该函数旨在清理沙箱中的异常，阻止泄露主机信息。然而，如果攻击者设置自定义 “getPrototypeOf()” 代理句柄抛出未清理的主机异常，则 “handleException” 函数将无法进行清理。这有助于攻击者“访问主机函数”即逃逸沙箱限制并在主机上下文中执行任意代码，从而可能发动严重攻击。  
  
Lee 指出，该漏洞影响3.9.1及之前所有版本。他还发布相关 PoC。  
  
建议所有集成 VM2 库的用户、包维护人员和软件开发人员，尽管升级至3.9.17版本，修复该漏洞。Seongil Wi 证实称 Lee 发现的这两个漏洞和CVE-2023-29017无关。  
  
遗憾的是，影响多数开源软件项目的供应链复杂性可能会延后升级受影响工具的 VM2。加上该漏洞的 PoC 已可公开访问，因此很多用户可能遭暴露风险的时间可能会延长。  
  
****  
  
****  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[VM2 JavaScript 沙箱库中存在严重的 RCE 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516192&idx=3&sn=8ab0a31dc71c4a46eafb1990c1f0f021&chksm=ea94b14adde3385cb974be6e0db2bac6737f0ffb278d0cb57922f45c53afcb115f38d3ad64de&scene=21#wechat_redirect)  
  
  
[JavaScript 沙箱 vm2修复远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514120&idx=3&sn=70433e477638c9c6b3ed925cbdb9cb76&chksm=ea948962dde300745c90d6d6c46d60584f699d5afcb625367d464f79bbbb7bf930be487ee4b9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-sandbox-escape-poc-exploit-available-for-vm2-library-patch-now/  
  
  
题图：Pixabay License  
  
  
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
  
