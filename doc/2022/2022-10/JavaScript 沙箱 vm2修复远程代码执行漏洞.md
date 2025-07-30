#  JavaScript 沙箱 vm2修复远程代码执行漏洞   
Ben Dickson  代码卫士   2022-10-08 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
热门的 JavaScript 沙箱环境 vm2 中存在一个bug，可导致恶意人员绕过沙箱防火措施并在主机设备上发动远程代码执行攻击。  
  
  
Vm2的每周下载量超过400万次，在Node.js服务器中创建了安全的上下文，在无需攻陷服务器的情况下运行不受信任代码。该漏洞的CVSS评分为10分，由于vm2用于生产环境和开发者环境中，其影响可能因此而加大。  
  
  
**有趣的技术**  
  
  
  
该漏洞是由Oxeye Security公司的两名研究员 Gal Goldshtein 和 Yuval Ostrovsky 发现的。他们指出，“我们评估给定软件安全性的方法通常是分析过去在该软件中出现过的安全问题。这有助于我们更好地抓住可用攻击面并可能从不完整的修复方案中找到容易发现的bug。在查看vm2维护人员此前收到的漏洞时，我们注意到一种有意思的技术：该漏洞报告人员滥用Node.js中的错误机制逃逸沙箱。”  
  
  
**沙箱和主机之间的信道**  
  
  
  
和此前在vm2中发现的多个bug一样，这个新发现的bug依赖于沙箱所使用的信道和主机机器通信。在本案例中，该bug是因为异常处理不当引发的。  
  
研究人员指出，“我们所发现的bug依赖于常见的虚拟机绕过方法，即在沙箱中找到能够和沙箱外元素结合的元素。发现这种连接后，攻击者就有机会和托管进程交互。”这种信道可导致攻击者在Node.js服务器上运行任意代码，包括调用运行系统命令的函数。  
  
该安全团队不久将发布相关漏洞详情。阻止exploit的唯一方法是升级到vm2的最新版本。  
  
  
**本意在运行不可信代码**  
  
  
  
研究人员表示，“这个库用于生产环境中丝毫不令人惊讶，主要原因在于它每个月的下载量超过1600万次。我们正在负责任地披露该漏洞。”  
  
RedHat 另外发布一份安全公告，说明了遭该漏洞影响的所有服务。  
  
这并非vm2首次修复沙箱绕过漏洞，说明了保护沙箱环境的困难之处。一般而言沙箱的作用是在一款应用程序中运行不可信代码，意味着你不应当自动假设沙箱是安全的。  
  
研究人员还表示，“如果使用沙箱是无法避免的，则推荐将应用程序的逻辑和敏感部分与运行沙箱代码的微服务隔离开，这样即使威胁行动者成功破解沙箱，攻击面也仅限于被隔离的微服务。”  
  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[25个恶意JavaScript 库通过NPM官方包仓库分发](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510675&idx=2&sn=a778ae74ffe2f1095ab0f758f7879a3b&chksm=ea949bf9dde312ef3baf0b0e2c892753ec74baa207331ff330547e90e5da4480464074b60f93&scene=21#wechat_redirect)  
  
  
[攻击者接管账户，攻陷周下载量超700万次的JavaScript 流行库 ua-parser-js](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508579&idx=1&sn=aecd181299b427ce216fa054582e4bb7&chksm=ea949309dde31a1f701510a4624092c3e8f3820563007da44068c23bf201b41320b3df356144&scene=21#wechat_redirect)  
  
  
[别问，问就是我差点在所有浏览器中注入 JavaScript 代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502887&idx=1&sn=1e0831abb23d12237d59f856a5f73496&chksm=ea94fd4ddde3745b97ea3c93fbeca9b04d58a9bc9af9b7cef182bb1cbf0d4f182277fb17fd9f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/javascript-sandbox-vm2-remediates-remote-code-execution-risk  
  
  
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
