#  Mozilla 修复Pwn2Own大赛发现的两个 Firefox 0day   
Sergiu Gatlan  代码卫士   2024-03-26 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Mozilla 公司发布安全更新，修复了研究人员 Manfred Paul 在 Pwn2Own 温哥华大赛中找到的两个 Firefox 0day 漏洞。**  
  
  
Manfred Paul 从Firefox浏览器中找到一个界外 (OOB) 写漏洞（CVE-2024-29943）实现远程代码执行权限，并利用另外一个威胁函数弱点 (CVE-2024-29944) 逃逸Firefox 沙箱。  
  
Mozilla 公司指出，第一个漏洞可导致攻击者通过利用易受攻击系统上基于范围的边界检查消除访问 JavaScript 对象界外。该公司解释称，“攻击者能够通过欺骗基于范围的边界检查消除在 JavaScript 对象上执行界外读或写。”第二个漏洞是经由事件句柄的JavaScript权限执行，可导致攻击者在Firefox Desktop web 浏览器的父进程中执行任意代码。Mozilla 在Firefox 124.0.1和Firefox ESR 115.9.1中修复了这些漏洞，阻止针对桌面设备上未修复 web 浏览器的代码执行攻击。  
  
Manfred Paul 利用并将这两个漏洞提交一天后，Mozilla 公司就修复了这两个漏洞。不过按照 Pwn2Own 大赛规则，厂商一般有90天的修复时间。  
  
Pwn2Own 温哥华大赛共发现29个唯一0day，颁发1132500美元赏金。Manfred Paul 以202500的赏金、25个积分点的成绩获得大赛冠军。除了 Mozilla 的两个0day 外，他还成功攻破苹果 Safari、谷歌 Chrome 和微软 Edge 浏览器。比赛第一天，他组合利用一个PAC绕过和整数下溢0day的组合在 Safari 中获得RCE权限，还演示了如何利用“对输入中特定数量验证不当”的双击RCE漏洞拿下 Chrome 和 Edge 浏览器。  
  
在Pwn2Own三次大赛（多伦多、东京汽车、温哥华）中，ZDI共计颁发3494750美元的赏金和两台特斯拉Model 3汽车。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Pwn2Own 2024温哥华大赛落幕  Master of Pwn 诞生](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519143&idx=1&sn=aa2842286dc5aa1063e21f010ec15ad1&chksm=ea94bacddde333db812ea8c9e259e4db299453970f32514ee6a500f954af29886650c4989674&scene=21#wechat_redirect)  
  
  
[Mozilla 修复Firefox 漏洞，可导致RCE和沙箱逃逸](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518467&idx=2&sn=a4b556d25e18fde4859318143fe831f9&chksm=ea94b869dde3317f0c3e37352a2db057bc26f539dfef7de56f39049b1a8ae269888c76c12e48&scene=21#wechat_redirect)  
  
  
[补丁星期二：微软、Adobe和Firefox纷纷修复已遭利用的 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517643&idx=1&sn=83e85b6b9bf3a9f0cf0c1843c9589950&chksm=ea94b4a1dde33db74b2b9c5ff5da439c9a2169fcab51d215bdc495affe02787d31ab6bcf7b98&scene=21#wechat_redirect)  
  
  
[Mozilla 修复Firefox 浏览器的多个高危漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515956&idx=2&sn=7870f9607adf1541eef5be5402a82ab4&chksm=ea948e5edde307489a6b2a77b80ba248729a3d0dbfd20a6b65ee00d181f4b422bc09fa95eb1c&scene=21#wechat_redirect)  
  
  
[Firefox 97.0.2 修复两个已遭利用的0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510779&idx=2&sn=ebffc30f51572f1abd513f92b810858b&chksm=ea949b91dde31287dee367059f7db5e2dd338e600e25a7139b08463e0b1acc74d939bf9baf0c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/mozilla-fixes-two-firefox-zero-day-bugs-exploited-at-pwn2own/  
  
  
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
  
