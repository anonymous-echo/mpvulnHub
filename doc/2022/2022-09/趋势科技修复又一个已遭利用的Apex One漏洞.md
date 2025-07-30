#  趋势科技修复又一个已遭利用的Apex One漏洞   
Eduard Kovacs  代码卫士   2022-09-14 18:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
本周二，趋势科技宣布称已修复位于 Apex One端点安全产品中的多个缺陷，其中包括一个0day。  
  
  
  
  
该漏洞的编号是CVE-2022-40139，是与回滚函数相关的一个验证不当问题，可导致代理下载未认证的回滚组件并执行任意代码。该高危漏洞仅可遭可登陆至该产品的管理面板的攻击者利用。  
  
趋势科技指出，“由于攻击者之前必须窃取产品管理面板的认证信息，因此仅利用该漏洞无法渗透目标网络。”  
  
目前趋势科技并未发布关于利用CVE-2022-40139漏洞的攻击活动信息。  
  
威胁行动者利用趋势科技产品漏洞的情况并不少见，过去几年来就曾发生过多起攻击。这些安全漏洞似乎多数被用于针对性攻击中。除了该漏洞外，Apex One 还修复了其它三个高危漏洞和两个中危漏洞。其中最严重的是CVE-2022-40144，可导致攻击者使用特殊构造的请求绕过认证。从理论上来讲，攻击者可组合利用这些漏洞和上述0day满足认证要求，不过趋势科技并未提到CVE-2022-40144已遭攻击。  
  
趋势科技修复的其它漏洞可用于提升权限、发动拒绝服务攻击并获取目标服务器的信息。  
  
从CISA列出的“已知的已遭利用漏洞类别“中可知，过去已收录8个其它已遭在野利用的漏洞，其中多数影响 Apex产品。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[趋势科技修复已遭利用的 Apex Central 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511227&idx=2&sn=3003d8d5ba53390d7d87aef04901daaa&chksm=ea949dd1dde314c74bd2b01478eb78507c4454c23c81eb2adbb6bec1115a9e6d1136f727d961&scene=21#wechat_redirect)  
  
  
[趋势科技称 Apex One EDR 平台的两个0day已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507161&idx=1&sn=17864c45b313691348a041867c8e49bf&chksm=ea94edb3dde364a548abd9ef7bd0bad0a97198ac369b5295f7ec8ff2548439eeb881ec79ec42&scene=21#wechat_redirect)  
  
  
[卡巴微软趋势科技等多款流行的反恶意软件产品被曝多个漏洞，可导致提权等后果](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495445&idx=1&sn=170cb8a1b7b063090129cfb9b53f67f5&chksm=ea94de7fdde35769648e71c26d8b9e1a5ba7bd758134fc882f3041b94270aad20bf41a5d544e&scene=21#wechat_redirect)  
  
  
[趋势科技企业级杀软产品俩 0day 已遭利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247492533&idx=1&sn=0baaa880d17fd06bbd674cb0b9ec7455&chksm=ea94d2dfdde35bc9ad833ab1cc1cc837e0f09f5ca92fa759a82681e6366048b724d836b9dd37&scene=21#wechat_redirect)  
  
  
[趋势科技反威胁工具集被曝 RCE 漏洞：如文件名是 cmd.exe 或 regedit.exe，则运行恶意软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491318&idx=1&sn=6f2f4e36936a1c672a1bb2ea28a91d80&chksm=ea972f9cdde0a68a983d165b76d539afd0f96a46343dc652329d4f42718682998b05ad5c558f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/trend-micro-patches-another-apex-one-vulnerability-exploited-attacks  
  
  
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
