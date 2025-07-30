#  苹果再次紧急修复两个0day漏洞   
Sergiu Gatlan  代码卫士   2023-10-07 15:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**苹果在上周三紧急修复了两个已遭利用的0day 漏洞（CVE-2023-42824和CVE-2023-5217）。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT0dBiaGpclhcOtescDEZQ9zwwTIibIqic8b3bzbebmv3JL1V7nnTaibicHzbSoyGXsVLA3sMHaB0FCOTA/640?wx_fmt=gif "")  
  
  
苹果公司发布安全公告指出，“苹果注意到报告称该漏洞被用于 iOS 16.6之前的版本。”第一个漏洞CVE-2023-42824因XNU内核中存在一个弱点引发，可导致本地攻击者在未修复的 iPhone 和 iPad 上实现提权。  
  
尽管苹果公司表示已通过改进检查在 iOS 17.0.3和 iPadOS 17.0.3 上修复了该漏洞，但尚未披露发现并报告该漏洞的人员。  
  
受影响设备范围广泛，包括：  
  
- iPhone XS及后续版本  
  
- iPad Pro 12.9英寸第二代及后续版本、iPad Pro 10.5英寸、 iPad Pro 11英寸第一代及后续版本、iPad Air 第3代及后续版本、iPad 第6代及后续版本以及iPad mini 第5代及后续版本。  
  
  
  
苹果修复的第二个新0day 是CVE-2023-5217，是由开源的libvpx 视频编码库的VP8 编码造成的，如被成功利用，可导致任意代码执行后果。虽然苹果并未将其标记为已遭在野利用，但谷歌和微软之前都曾这个漏洞。该漏洞是由谷歌TAG团队研究员发现的。  
  
  
**今年已修复18个已遭利用0day**  
  
  
  
  
CVE-2023-42824是苹果自今年年初以来修复的第17个已遭利用漏洞。  
  
最近，苹果公司还修复了由公民实验室和谷歌TAG团队发现的三个0day漏洞CVE-2023-41991、CVE-2023-41992和CVE-2023-41993。上个月，公民实验室披露了两个0day漏洞CV-E2023-41061和CVE-2023-41064，它们被用于零点击利用链BLASTPASS中，利用NSO 集团的Pegasus 监控软件感染已被完全修复的iPhone。  
  
其它0day漏洞包括：  
  
- 7月修复两个0day：CVE-2023-37450和CVE-2023-38606  
  
- 6月修复3个0day：CVE-2023-32434、CVE-2023-32435和CVE-2023-32439  
  
- 5月修复3个0day：CVE-2023-32409、CVE-2023-28204和CVE-2023-32373  
  
- 4月修复2个0day：CVE-2023-28306和CVE-2023-28205  
  
- 2月修复了1个Webkit 0day：CVE-2023-23529  
  
  
  
今天发布的 iOS 17.0.3 还修复了导致运行 iOS 17.0.3及以下版本的iPhone 过热的一个已知问题。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[苹果紧急修复已遭利用的3个0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517726&idx=1&sn=6812214f8fc21189da02ba2731b87720&chksm=ea94b774dde33e62737863151185ae158018de3e7f683d689e2a466982db356c57f6d7c1de92&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=1&sn=f4c64820b9383523f48091354491d150&chksm=ea94b4f5dde33de3f2f7c7d26b6bc5178d7deb13b62b5e3b5220b9ad188751bce855b427f00b&scene=21#wechat_redirect)  
  
  
[新Windows?! 苹果再修复已遭利用的新0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=2&sn=cfa4e9c7c012a88ff6a1ca8ada75564c&chksm=ea94b543dde33c556be2fcb984ebb556ca8d5f6654c7938d9996636b045518ace000eb82f2b6&scene=21#wechat_redirect)  
  
  
[苹果员工在CTF大赛发现谷歌0day秘而不报 $10000赏金由他人获得](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517155&idx=1&sn=9af2d4f8742d395b46b7d44e219d9b05&chksm=ea94b289dde33b9f559073d1207e8437f82e8b6acf046825ee7f690fcbe59f72977119ba7dae&scene=21#wechat_redirect)  
  
  
[苹果紧急修复已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516996&idx=1&sn=99077b8f872c126bf4abbae8c76123fc&chksm=ea94b22edde33b3872fa9d5e8336be03c61f1dbca04bd5821d460d5e0fcd1915fb4c2e9163a3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/apple/apple-emergency-update-fixes-new-zero-day-used-to-hack-iphones/  
  
  
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
  
