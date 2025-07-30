#  Chrome修复已遭活跃利用的0day   
Ravie Lakshmanan  代码卫士   2025-05-16 10:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**本周三，谷歌发布更新修复了Chrome web浏览器中的四个安全漏洞，其中一个已出现在野利用。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMR4Qnibgrz8KDejOwhdVzksDqZ5jJlQ9ExBlHEbRK1Tv91llwt9SicDFIoAveXg38wmIro3BnQ2mq0Q/640?wx_fmt=png&from=appmsg "")  
  
  
该高危漏洞的编号是CVE-2025-4664，是位于组件Loader中的策略执行不充分问题。谷歌提到，“Google Chrome 136.0.7103.113之前版本中对Loader策略执行不充分，可导致远程攻击者通过构造的HTML页面泄露跨源数据。”  
  
该漏洞由安全研究员 Vsevolod Kokorin 发现，谷歌提到“CVE-2025-4664的利用已在野出现”。Kokorin 在本月早些时候提到，“和其它浏览器不同，Chrome 在子资源请求上解析 Link 标头。问题在于该Link标头可设置 referrer-policy。我们可以指定unsafe-url并捕获完整的查询参数。”  
  
Kokorin 还提到，这些查询参数包含敏感数据，可导致账号遭完全接管，而攻击者可通过来自第三方资源的一张图片盗取该查询参数信息。  
  
目前尚不清楚CVE-2025-4664是否已遭恶意利用。该漏洞是继 CVE-2025-2783以来的第二个遭在野“活跃利用”的漏洞。  
  
建议用户将 Chrome 浏览器更新至 136.0.7103.113/.114（Windows 和 Mac系统）以及 136.0.7103.113（LInux）版本。建议其它基于Chromium 浏览器如 Edge、Brave、Opera和 Vivaldi 的用户及时应用补丁。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Chrome 136修复已存在20年的浏览器历史隐私风险](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522738&idx=1&sn=39cacf3a0690629e9d07409fb8f9d0d3&scene=21#wechat_redirect)  
  
  
[Firefox 存在严重漏洞，类似于 Chrome 已遭利用0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522612&idx=2&sn=50c7ad88e87b485a09c7ae916f9d9677&scene=21#wechat_redirect)  
  
  
[Chrome 修复 Lens 特性中的严重 UAF 漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522548&idx=2&sn=0cc9b1e732d2a5c231ebd3f08b1198d4&scene=21#wechat_redirect)  
  
  
[多个Chrome扩展在供应链攻击中遭攻陷](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521944&idx=2&sn=8d1b7899e6da840d037a71c74451e5c2&scene=21#wechat_redirect)  
  
  
[Chrome 131 更新修复高危内存安全漏洞，其中1个获奖5.5万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=2&sn=342840d67c1fbf01af15a41ea7621df8&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/05/new-chrome-vulnerability-enables-cross.html  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
