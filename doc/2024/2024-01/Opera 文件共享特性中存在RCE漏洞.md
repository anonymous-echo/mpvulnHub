#  Opera 文件共享特性中存在RCE漏洞   
Ionut Arghire  代码卫士   2024-01-17 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Guardio Labs 发布报告指出，用于设备之间共享文件的 Opera 浏览器特性中存在一个漏洞，可导致 RCE 后果。**  
  
  
受影响的特性 My Flow 允许用户仅使用 Opera 的移动应用扫描一个 QR码就轻松在桌面和移动设备上交换信息和文件。一旦扫描QR码，用户就会看到所显示的类似聊天的接口，可立即执行所共享的文件。这一特性虽然方便用户但也使用户面临安全风险。  
  
研究人员支出，“这说明，网页上下文可从某种程度上与系统API进行交互，执行文件系统中的文件，而不受浏览器通常的限制条件，无沙箱无限制。”  
  
安全研究员从这一假设触发，开始深挖 Opera 用于识别可被恶意利用的架构、开发和安全协议。在调查过程中，他们发现 My Flow 特性使用的一个内置浏览器扩展 “Opera Touch Background” 具有广泛权限，尽管浏览器实现了很多限制和安全检查来阻止代码注入攻击和其它类型的恶意滥用情况。  
  
其中一个安全机制确保只有声明域下的web资源可与底层扩展进行通信，且只能使用特定的API。即使攻击者能够操纵此类资源增加自己的脚本，也必须绕过一个哈希值检查。  
  
然而，研究人员发现，My Flow 着陆页有多个版本，其中一些版本已存在多年且缺少更新的安全检查。研究人员提到，“这正是攻击者所需要的——不安全的、被遗忘的、易受代码注入攻击，且更重要的是——具有对高权限原生浏览器API的访问权限。”  
  
研究人员据此创建了 PoC 扩展，在受害者计算机上下载并执行文件。这一扩展将创建虚假的设备实例，生成与浏览器配对的QR码，之后模拟文件传输，向受害者浏览器传播恶意 payload。  
  
研究人员表示，攻击要求用户交互但通过社工就能轻松绕过：用户安装该扩展后会收到“谢谢”的信息，在屏幕上任意地方点击一次就能触发 payload 执行。  
  
在实践中，攻击者将创建恶意扩展，诱骗受害者进行安装，并在不到一秒钟的时间内在 Windows 或 macOS 系统上执行恶意代码。  
  
  
**已修复**  
  
  
  
  
  
该漏洞影响 Windows 和 macOS 系统上的 Opera 和 Opera GX 浏览器，已在2023年11月的服务器端修复。研究人员表示并未发现漏洞遭在野利用的证据。  
  
Opera 证实称已在11月17日获悉该漏洞并在22日部署了修复方案。Opera 指出，“我们当前使用的是HTML 标准结构，是不会破坏关键功能的最安全选择。Guardio 公司告知我们这个漏洞后，我们清除了这些问题的诱因并确保未来不会发生类似问题。同时，我们在扩展商店中通过人工审计，检测任何恶意扩展并在推给用户前将其列入黑名单。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开发人员：Opera浏览器的VPN等同于代理服务器](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485772&idx=5&sn=8f47bc6d1d8ec16c5a37571894827af8&chksm=ea973826dde0b130ee7a6e7aa52d4cdc5c47b9353f39c7cebbe7776bb0a72f1f9e4c3477ddb9&scene=21#wechat_redirect)  
  
  
[Chrome 漏洞多：web 浏览器还安全吗？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516843&idx=2&sn=08d47901f423ad544f407dead0344eef&chksm=ea94b3c1dde33ad7879cb6a504aa623576e7d749f80f139f04f047b1e28a6e6d949bea885041&scene=21#wechat_redirect)  
  
  
[Mozilla 修复Firefox 浏览器的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515956&idx=2&sn=7870f9607adf1541eef5be5402a82ab4&chksm=ea948e5edde307489a6b2a77b80ba248729a3d0dbfd20a6b65ee00d181f4b422bc09fa95eb1c&scene=21#wechat_redirect)  
  
  
[谷歌决定不修复这个Chromium浏览器XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514671&idx=1&sn=61fcdf93bfac81f15a8003972cd54cfd&chksm=ea948b45dde3025344d546821417c7d84002e20f4ce07d501debfcd2eb37b63ca343e65307ca&scene=21#wechat_redirect)  
  
  
[谷歌修复7个 Chrome 浏览器漏洞，CISA建议尽快更新](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512301&idx=2&sn=8692c38f4cf01bc6ae31e903937819f7&chksm=ea948187dde30891f434d90835b849b48564c5b0c642973efc1eb86324af13f3c4f1bfaefbe9&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/remote-code-execution-vulnerability-found-in-opera-file-sharing-feature/  
  
  
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
  
