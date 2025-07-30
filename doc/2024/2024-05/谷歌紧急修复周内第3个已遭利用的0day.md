#  谷歌紧急修复周内第3个已遭利用的0day   
Sergiu Gatlan  代码卫士   2024-05-16 11:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Chrome 发布紧急 Chrome 安全更新，修复了一周内已遭利用的第3个 0day 漏洞。**  
  
  
  
谷歌在本周三的安全公告中提到，“谷歌发现 CVE-2024-4947的一个在野利用。” 谷歌发布125.0.6422.60/.61 Mac/Windows版和 125.0.6422.60 Linux版，修复了这个漏洞。这些新版本将在未来几周内向 Stable Desktop 渠道中的所有用户推出。  
  
Chrome 会在安全补丁可用时自动更新。不过用户也可去 Chrome 目录＞帮助＞关于谷歌 Chrome 目录检查自己是否运行最新版本，完成更新，之后点击“重启”按钮进行安装。本文作者发现 Chrome 更新现在已可用。  
  
CVE-2024-4947是一个高危0day，是由 Chrome V8 JavaScript 引擎中的一个类型混淆弱点引发的，由卡巴斯基研究员 Vasily Berdnikov 和 Boris Larin 报送。  
  
尽管这类漏洞通常可导致威胁行动者通过读或写缓冲区边界外的内存的方式触发浏览器崩溃，但也可被用于在目标设备上执行任意代码。虽然谷歌证实称该漏洞已遭利用，但并未发布更多详情，以便用户有充足时间进行修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSUuiaor0We6ichs4X8iaYdtVIex1zbNL4UtAd76TjagShJg8CmSES99H5PL0aWGsgvhL0I0G80c0HuA/640?wx_fmt=gif&from=appmsg "")  
  
**2024年修复的第7个已遭利用0day**  
  
  
  
  
  
该漏洞是今年以来谷歌修复的第7个已遭利用 Chrome 0day 漏洞，其它6个包括：  
  
- CVE-2024-0519：位于 Chrome V8 JavaScript 引擎中的一个高危界外内存访问弱点，可导致远程攻击者通过特殊构造的HTML页面利用堆损坏漏洞，导致攻击者越权访问敏感信息。  
  
- CVE-2024-2887：位于 WebAssembly (Wasm) 标准中的高危类型混淆漏洞，可导致攻击者通过构造的HTML页面实现远程代码执行利用。  
  
- CVE-2024-2886：位于 web 应用程序所使用 WebCodecs API 中的释放后使用漏洞，可被远程攻击者通过构造的HTML页面执行任意读和写，导致远程代码执行后果。  
  
- CVE-2024-3159：由 Chrome V8 JavaScript 引擎中界外读引发的高危漏洞。远程攻击者可使用特殊构造的HTML页面访问所分配内存缓冲区以外的数据，导致堆损坏，从而提取敏感信息。  
  
- CVE-2024-4671：位于负责处理浏览器中渲染和显示内容的 Visuals 组件中的一个高危释放后使用漏洞。  
  
- CVE-2024-4761：位于 Chrome V8 JavaScript 引擎中的界外写漏洞。该引擎负责在应用程序中执行已有JS代码。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复今年第五个 Chrome 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519462&idx=1&sn=1f7824cfd17d3489bc4ba1b37c5d974c&chksm=ea94bd8cdde3349a09b38fe57ced58ecc0d6aa9cd8270a10e3ef522071c83b0a7ae0fc2e14a6&scene=21#wechat_redirect)  
  
  
[谷歌修复 Pwn2Own 2024大赛发现的两个 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519170&idx=1&sn=31612ff9461ff59184a818b76f04c198&chksm=ea94baa8dde333be86a1b2054ea40407dfa5a45d469b948ac55085e5f64e7872f7e2007c90ad&scene=21#wechat_redirect)  
  
  
[谷歌修复2024年首个已遭利用的 Chrome 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518705&idx=2&sn=1f6ee90c31f7b70d13390d0a735fe85f&chksm=ea94b89bdde3318da0dc7cd16e5e35198256a22c9c7f0dfa9132e438f6a90fa78fc85e7a63bf&scene=21#wechat_redirect)  
  
  
[CISA：注意 Chrome 和 Excel 解析库中已遭利用的开源漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518582&idx=2&sn=3e7fcf93d7c3d8fa193fcb72ed6c2347&chksm=ea94b81cdde3310af6e572040db0f7c2aba6bf5314cdb417d0ad4e7fffa194153e99860228a1&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复今年第8个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518459&idx=1&sn=16639910e34f9b7b38277934cf352d7e&chksm=ea94b991dde330870c970cec3c63ccbdb8634f61116a675b4e1ec25c90e9fc4ae7bd5fd02a04&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/google/google-patches-third-exploited-chrome-zero-day-in-a-week/  
  
  
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
  
