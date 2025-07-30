#  Firefox 存在严重漏洞，类似于 Chrome 已遭利用0day   
Ravie Lakshmanan  代码卫士   2025-03-28 17:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Mozilla 公司发布更新，修复了影响其 Firefox Windows 版本的一个严重漏洞，而该漏洞与此前已遭利用的 Chrome 0day类似。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTrq3rS3Q6ZCGx4fz5qic1iaRG3SCU4zcDzOx72TBqiahia8EpBu3SgAuicXdQfiaXFElg9GD0WSFuxdOEQ/640?wx_fmt=png&from=appmsg "")  
  
  
Mozilla 公司修复的漏洞编号是CVE-2025-2857，是一个不正确的句柄，可导致沙箱逃逸。Mozilla 在安全公告中提到，“根据最近的Chrome 沙箱逃逸漏洞 (CVE-2025-2783)，多名Firefox 开发人员在我们的IPC（进程间通信）代码中发现了一个类似模式。受攻陷的子进程可导致父进程返回预期之外的强大句柄，从而导致沙箱逃逸。”  
  
该漏洞影响 Firefox 和 Firefox ESR，已在Firefox 136.0.4、Firefox ESR 115.21.1和Firefox ESR 128.8.1中修复，未有证据表明该漏洞已遭在野利用。  
  
此前不久，谷歌发布Chrome 134.0.6998.177/.178 Windows 版本，修复漏洞CVE-2025-2783。该漏洞已遭在野利用，是针对俄罗斯新闻媒体、教育机构和政府组织机构开展的攻击的一部分。卡巴斯基在2025年3月中旬检测到该攻击，并提到感染发生在受害者点击钓鱼邮件中特殊构造链接，通过Chrome 打开受攻击者控制的网站后发生。  
  
据称，CVE-2025-2783与Chrome 浏览器中的一个未知利用组合用于突破沙箱限制并实现远程代码执行后果。修复该漏洞有效地拦截了整个攻击链。美国CISA之后将漏洞纳入必修清单，要求联邦机构在4月17日之前应用必要的缓解措施。  
  
建议用户将浏览器实例更新至最新版本，阻止潜在风险。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Chrome 修复 Lens 特性中的严重 UAF 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522548&idx=2&sn=0cc9b1e732d2a5c231ebd3f08b1198d4&scene=21#wechat_redirect)  
  
  
[多个Chrome扩展在供应链攻击中遭攻陷](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521944&idx=2&sn=8d1b7899e6da840d037a71c74451e5c2&scene=21#wechat_redirect)  
  
  
[谷歌紧急修复已遭利用的0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522590&idx=2&sn=ee575193ee5fe0995b313a95a46890ee&scene=21#wechat_redirect)  
  
  
[Chrome 131 更新修复高危内存安全漏洞，其中1个获奖5.5万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=2&sn=342840d67c1fbf01af15a41ea7621df8&scene=21#wechat_redirect)  
  
  
[谷歌修复由苹果报送的严重 Chrome 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521342&idx=1&sn=355a1e1a938422e3437d8a957f360c7e&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/03/mozilla-patches-critical-firefox-bug.html  
  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
