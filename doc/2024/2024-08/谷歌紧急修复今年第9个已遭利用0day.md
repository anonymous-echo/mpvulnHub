#  谷歌紧急修复今年第9个已遭利用0day   
Sergiu Gatlan  代码卫士   2024-08-22 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌发布Chrome 紧急更新，修复了一个已遭利用的0day漏洞 (CVE-2024-7971)。**  
  
该漏洞是一个高危0day漏洞，由 Chrome V8 JavaScript 引擎中的一个类型混淆弱点引发。微软威胁情报中心和微软安全响应中心的研究员在本周一报送了该漏洞。  
  
尽管这类漏洞通常可导致攻击者在被分配到内存中的数据解释为不同类型漏洞后触发浏览器崩溃，但可被用于在运行未修复浏览器的目标设备上执行任意代码。  
  
谷歌已在适用于 Windows/macOS 的版本 128.0.6613.84/.85和适用于Linux 的版本128.0.6613.84中修复了该0day漏洞。这些版本将在未来几周向Stable Desktop的所有用户推出。  
  
虽然Chrome 更新会在安全补丁推出时自动更新，不过用户也可在“Chrome 目录＞帮助＞关于Google Chrome”，点击更新完成并点击“重启”按钮安装。  
  
尽管谷歌已证实该漏洞已遭在野利用，但并未分享其它详情，以便用户有足够时间修复。  
  
这是谷歌在2024年以来修复的第9个已遭活跃利用的0day漏洞，其它漏洞包括：  
  
- CVE-2024-0519：位于Chrome V8 JavaScript 引擎中的高危界外内存访问弱点，可导致远程攻击者通过特殊构造的 HTML 页面利用堆损坏，导致敏感信息遭越权访问。  
  
- CVE-2024-2887：位于WebAssembly (Wasm) 标准中的一个高危类型混淆漏洞，可导致攻击者利用构造的HTML页面实现远程代码执行利用。  
  
- CVE-2024-2886：位于WebCodecs API 中的UAF漏洞，可被远程攻击者通过构造的 HTML 页面用于执行任意读和写，从而执行远程代码。  
  
- CVE-2024-3159：由 Chrome V8 JavaScript 引擎中界外读引发的高危漏洞。远程攻击者可利用特殊构造的HTML页面，利用该漏洞访问所分配内存缓冲区以外的数据，导致堆损坏，从而提取敏感信息。  
  
- CVE-2024-4671：位于负责处理在浏览器中渲染和展示内容的Visuals 组件中的高危UAF漏洞。  
  
- CVE-2024-4761：位于Chrome V8 JavaScript 引擎中的界外写漏洞。  
  
- CVE-2024-4947：位于 Chrome V8 JavaScript引擎中的类型混淆漏洞，可用于在目标设备上执行任意代码。  
  
- CVE-2024-5274：位于 Chrome V8 JavaScript 引擎中的类型混淆漏洞，可导致崩溃、数据损坏或任意代码执行后果。  
  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复已遭利用的安卓内核0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520345&idx=2&sn=e480c7108b41c03d874e5bd6bc1c39bf&chksm=ea94a133dde3282563f26f94c29d3b95b05a082b1c377d83aa2ef24ce6e26794bc98899319d7&scene=21#wechat_redirect)  
  
  
[谷歌：Pixel 固件0day漏洞已遭活跃利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519734&idx=1&sn=fcc36eded6f81b0c6a5496090527e207&chksm=ea94bc9cdde3358abfe399d7142f16536018699b0dedc6a6d9566915c0a7341a60b1d647e397&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复周内第3个已遭利用的0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519506&idx=1&sn=6a998af125698c3afd195f3d1eb96981&chksm=ea94bc78dde3356e58d441d5787adcdb360f70675c569aa3b7e5d7d549868bea76393657c2bd&scene=21#wechat_redirect)  
  
  
[谷歌修复今年第五个 Chrome 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519462&idx=1&sn=1f7824cfd17d3489bc4ba1b37c5d974c&chksm=ea94bd8cdde3349a09b38fe57ced58ecc0d6aa9cd8270a10e3ef522071c83b0a7ae0fc2e14a6&scene=21#wechat_redirect)  
  
  
[谷歌修复遭取证公司利用的两个 Pixel 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519231&idx=1&sn=5f9f5009dffb1ec140664df249e99fae&chksm=ea94ba95dde33383baddf488f4094e6fa0cd272867dd83693a008407c6112765694a7f8ef1d6&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/google-fixes-tenth-actively-exploited-chrome-zero-day-in-2024/  
  
  
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
  
