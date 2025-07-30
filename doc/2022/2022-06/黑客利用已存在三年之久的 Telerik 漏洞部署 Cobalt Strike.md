#  黑客利用已存在三年之久的 Telerik 漏洞部署 Cobalt Strike   
Bill Toulas  代码卫士   2022-06-17 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxFSUORBBuUtbhq53ibjE2c8z1NzWaiaRKZrK0pahtib0YzibCMwMmVnUCvw/640?wx_fmt=png "")  
  
威胁组织 “Blue Mockingbird” 利用 Telerik UI 漏洞 (CVE-2019-18935) 攻陷服务器，安装 Cobalt Strike 信标并通过劫持系统资源挖掘门罗币。  
  
  
  
该漏洞是“严重”的反序列化漏洞（CVSS评分9.8），可导致在 ASP.NET AJAX 的 Telerik UI 库中执行远程代码。  
  
Blue Mockingbird 黑客组织还在2020年5月利用该漏洞攻击使用 Telerik UI的微软IIS服务器，而此时距离厂商发布安全更新已过去一年的时间。  
  
令人惊讶的是，Sophos 公司的研究员指出，该黑客组织仍然在利用该漏洞发动网络攻击。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxcoGkFjdqUktU90aTSOP8YOYH0zibcdjowWJAc07wDjuTMRmrSibvELQw/640?wx_fmt=gif "")  
  
**利用老旧漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxSicWibaXEsrZIiaQalA7TXgAUKcNUFrVibUGdaqxiaIynRxfxev8IFIPsCw/640?wx_fmt=png "")  
  
  
  
为利用该漏洞，攻击者必须获得加密密钥，保护 Telerik UI 在目标上的序列化。攻击者可通过利用目标 web app 中的另外一个漏洞或利用CVE-2017-11317和CVE-2017-11357实现这一目的。  
  
由于很多 web 应用是在开发之时就嵌入该 Telerik UI 框架版本并在之后不再继续或者将其忘记，因此仍然存在有效的攻击目标。一旦获得密钥，攻击者就能够编译包含该代码的恶意DLL，在反序列化过程中执行并且在 “w3wp.exe” 进程上下文中运行。  
  
Sophos 公司在最近的攻击中发现，Blue Mockingbird 组织利用现成可用的PoC exploit 处理该加密逻辑并将DLL编译自动化。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxG1E0fEI9iajQ7aQwVrtUa8Q26H0qD1Fytib0l8gDRxRNkxPBw8iavtSgg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxcoGkFjdqUktU90aTSOP8YOYH0zibcdjowWJAc07wDjuTMRmrSibvELQw/640?wx_fmt=gif "")  
  
**受经济利益驱动的攻击**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxSicWibaXEsrZIiaQalA7TXgAUKcNUFrVibUGdaqxiaIynRxfxev8IFIPsCw/640?wx_fmt=png "")  
  
  
  
最近攻击活动中使用的payload 是 Cobalt Strike 信标，它是Blue Mockingbird 滥用于执行已编码 PowerShell 命令的合法渗透测试工具。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxFwDNHN2c3u934vMNU0aNccX4k1icZQLvvUnChh69SJLJ37SvkL9MNBg/640?wx_fmt=png "")  
  
  
攻击者通过GPOs 创建用包含base64编码的PowerShell 的新注册表项编写的调度任务，从而实现持久性。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxWoYkNIWeSVkg3BqbRbzA3dhppP3ibkU7NmZIKvdvAya8nuzexp5JeTg/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsx6ZysPHtq6c5WMZJPPibx25VkAxMDVmtvweT276nzqsrXhanaiaQm2Xng/640?wx_fmt=png "")  
  
  
脚本使用常见的AMSI绕过技术，逃避 Windows Defender 检测，下载并将 Cobalt STRIKE DLL加载到内存中。  
  
第二阶段的可执行文件 (‘crby26td.exe’) 是XMRig Miner，是标准的开源密币挖矿机，用于挖掘追踪难度最大的密币之一，门罗币。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxWCDhpPEuYqXBJLw18yVlWunJJGGIAibDDgXoTiaibaWFGDSveia8tOMIlQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRAVDPHJ7M6kljtWC53nXsxcLf21gp3M3tt2rPJGUPVyd2b7atxauG17YuFbHhh7RgwHib0O7WssGw/640?wx_fmt=png "")  
  
  
值得注意的是，这是Blue Mockingbird组织在2020年攻击活动中的主要目标，其整个攻击链、技术和目标并未发生太多改变。然而，部署 Cobalt Strike 创建了在受陷网络中轻松进行横向移动、窃取数据、接管账户和部署更多payload如勒索软件的方法。目前尚无法确定该黑客组织是否有意探索这些场景，不过目前它们的目标是门罗币挖掘。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[三年蜜罐实验：黑客想从物联网设备中得到什么？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509831&idx=2&sn=85daf5b71f3529e32628b548b7069d5a&chksm=ea94962ddde31f3b92164d0349c9055c886dc0b41d8f6a9e6eb9ac73639a07b53b0dfa687a1b&scene=21#wechat_redirect)  
  
  
[三个已存在15年的 Linux 内核漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502285&idx=3&sn=a361962abe0bc11ea02be197d9f4a021&chksm=ea94f8a7dde371b1ae73e1f811d6ea337c28dde209ef16a90c3bc46a5c62654047fa9f584abb&scene=21#wechat_redirect)  
  
  
[US-CERT 公布近三年遭利用频率最高的十大安全漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247493095&idx=1&sn=3fa3dbe1a0b569a2845ad56d3a68959f&chksm=ea94d48ddde35d9bafd0e701ee56b4c1b8d1d8a44992a5fd35d4ee2ba0dd83a250de87d5bdc3&scene=21#wechat_redirect)  
  
  
[2019年第三季度谷歌及其用户受国家黑客攻击的情况说明](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491705&idx=1&sn=5dcb5a3c3808e3021bd8a72d6e74b06e&chksm=ea94d113dde35805db925b6494c4a402ea5647a330d291ecd1d6c584afd0eeb4adcd90c435fd&scene=21#wechat_redirect)  
  
  
[三年多无需密码即可访问后门账户：Docker 官方镜像被曝严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247489921&idx=4&sn=65080808985891c755efbe5ea0df9832&chksm=ea9728ebdde0a1fdf664f28ee350ee16e60458d0479f879dcee923216370ba3249aaf45d28a5&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-three-year-old-telerik-flaws-to-deploy-cobalt-strike/  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
