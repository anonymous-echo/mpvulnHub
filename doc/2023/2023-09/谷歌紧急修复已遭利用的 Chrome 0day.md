#  谷歌紧急修复已遭利用的 Chrome 0day   
Sergiu Gatlan  代码卫士   2023-09-12 12:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**谷歌发布紧急安全更新，修复了今年以来已遭利用的第四个 Chrome 0day 漏洞 (CVE-2023-4863)。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTQjG0tsKz3zHp96paO8kcyoSbmromEoPPZe5Pv5KDdKTDrTPj6qMDKgibluDVKspZ48qrB5hlNMJg/640?wx_fmt=png "")  
  
  
  
谷歌在周一发布的安全公告中指出，“谷歌发现在野存在 CVE-2023-4863的利用。”新版本目前推给 Stable 和 Extended 稳定频道用户，预计将在未来几天或几周的时间内推送给所有用户。  
  
建议 Chrome 用户将浏览器更新至 116.0.5845.187版本（Mac 和 Linux）以及116.0.5845.187/.188 (Windows) 版本。用户可直接通过 Chrome目录＞帮助＞关于 Google Chrome 直接获取。Chrome 也会自动检查是否存在新的更新并在重启后无需用户交互自动安装。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTQjG0tsKz3zHp96paO8kcyCHOaqygozKWiaQsF2libfECKibO2PmhbqGqbEIl2s09KaluOic2NXsibkyQ/640?wx_fmt=png "")  
  
**详情未披露**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTQjG0tsKz3zHp96paO8kcyDr7U4sfjKnmtUPll2LGLHdV6GicKYqVlCQV9p9AGdamrgwCoDS9b4CA/640?wx_fmt=png "")  
  
  
  
该严重漏洞是由 WebP 堆缓冲溢出弱点引发的，可造成崩溃、任意代码执行等影响。该漏洞由苹果安全工程和架构 (SEAR) 以及公民实验室在上周三报送。  
  
公民实验室的安全研究人员警察发现并披露被受政府支持威胁组织用于高针对性攻击中的 0day 漏洞，这些攻击的对象是全球反对派政客、记者和异见人士。  
  
上周四，苹果修复了由公民实验室发现的两个0day 漏洞，这两个漏洞被纳入 BLASTPASS 利用链，通过 NSO 集团的 Pegasus 商用间谍软件攻击完全打补丁的 iPhone 设备等。  
  
虽然谷歌表示，CVE-2023-4863已遭在野利用，但尚未发布更多相关详情。谷歌指出，“在大多数用户更新之前将限制漏洞详情和连接。如果漏洞存在于其它项目依赖但尚未修复的第三方库，则我们将保留这种限制。”也就是说，在发布更多技术详情之前，Chrome 用户可更新浏览器避免遭攻击。详情如发布，则意味着更多威胁人员可创造自己的 exploit 并在野部署。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复今年的第二个已遭利用 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516282&idx=1&sn=52eb5c1094115b783391abfa147ff39a&chksm=ea94b110dde3380674f5e90137e75fac973293e981e63b279fe6617e8a82bd25e2a2d066eccf&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复2023年第一个已遭利用的 Chrome 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516252&idx=1&sn=8371d9c05433cba2f5df47f101e8ad05&chksm=ea94b136dde33820c0033b8827312e06fe8bf7770075580020919000bdd6049133fc97d2a49e&scene=21#wechat_redirect)  
  
  
[苹果紧急修复两个已遭利用的 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517599&idx=1&sn=f4c64820b9383523f48091354491d150&chksm=ea94b4f5dde33de3f2f7c7d26b6bc5178d7deb13b62b5e3b5220b9ad188751bce855b427f00b&scene=21#wechat_redirect)  
  
  
[谷歌修复已遭利用的安卓 0day漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517584&idx=1&sn=37b84a3349271c0f40eb59108b6ebf14&chksm=ea94b4fadde33decfc9df5392f6bb398a7c9f557bfde7dc94564b2459d97d2285e8da38936db&scene=21#wechat_redirect)  
  
  
[Rapid7 2023年中威胁局势回顾：勒索攻击ROI仍高居不下；0day 漏洞利用规模扩大](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517476&idx=1&sn=0c931ea491e1ceec5bc4d0c6633d9fea&chksm=ea94b44edde33d587886a4ead4f7e7be77d88f83456be4274728de062d3cbe95501c219bff65&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/google/google-fixes-another-chrome-zero-day-bug-exploited-in-attacks/  
  
  
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
  
