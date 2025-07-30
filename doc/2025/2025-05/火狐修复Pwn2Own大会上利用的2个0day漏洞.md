#  火狐修复Pwn2Own大会上利用的2个0day漏洞   
Ravie Lakshmanan  代码卫士   2025-05-20 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Mozilla 公司已发布安全更新，修复位于火狐浏览器中的两个严重漏洞。这两个漏洞可被用于访问敏感数据或实现代码执行。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTMWKRs9VgAS5xbzGOobUgX5KB97XS7cJ9ZPlZrZorialpZZnPZktswibhtfuhsmyLA3iaY8LcvGdvPA/640?wx_fmt=png&from=appmsg "")  
  
  
这两个漏洞均在刚刚结束的柏林 Pwn2Own 大赛上遭利用，简述如下：  
  
- CVE-2025-4918：解析 Promise 对象时触发的界外访问漏洞，可导致攻击者在 JavaScript Promise 对象上读或写。  
  
- CVE-2025-4919：优化线性求和时触发的界外访问漏洞，可导致攻击者通过混淆数组指数大小，在 JavaScript 对象上执行读或写。  
  
  
  
换句话说，成功利用其中任何一个漏洞均可导致攻击者实现界外读或界外写，之后被滥用于访问敏感信息或导致内存损坏，为后续代码执行做准备。这些漏洞影响火狐浏览器如下版本：  
  
- 火狐浏览器138.0.4之前的所有版本（包括安卓版）  
  
- 火狐浏览器128.10.1之前的所有延伸支持发布 (ESR)  
  
- 火狐浏览器115.23.1之前的所有版本  
  
  
  
Palo Alto Networks 公司的研究员 Edouard Bochin 和 Tao Yan 发现并报送了漏洞CVE-2025-4918，而另外一个漏洞由Manfred Paul 发现并报送。值得一提的是，这两个漏洞均在Pwn2Own 柏林大赛上进行了演示且每个漏洞的赏金均为5万美元。  
  
随着web浏览器持续成为恶意软件传播的有吸引力的向量，建议用户将实例更新至最新版本以应对潜在威胁。Mozilla 公司在一份声明中表示，“这些攻击均未能突破我们的沙箱，即获得对用户系统的控制权限。尽管这些攻击的影响有限，但仍然建议所有用户和管理员尽快更新火狐浏览器。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[2025 Pwn2Own 柏林黑客大赛落下帷幕 Master of Pwn 诞生](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523052&idx=1&sn=4df3d545b249e2eb91adcbfd5893330b&scene=21#wechat_redirect)  
  
  
[2025年Pwn2Own柏林大赛奖金和目标公布](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522389&idx=1&sn=6ae18cd3962e778a6a16fb1f74a1b7aa&scene=21#wechat_redirect)  
  
  
[俄黑客组织 RomCom 被指利用火狐和Windows 0day攻击用户](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521617&idx=1&sn=cc6372f588d0fbc52027797f7d23ae53&scene=21#wechat_redirect)  
  
  
[火狐修复神秘的严重漏洞，同时影响Chrome 浏览器](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499209&idx=3&sn=8918330d97c1466dd0cbdb7269b05fa7&scene=21#wechat_redirect)  
  
  
[Chrome 136修复已存在20年的浏览器历史隐私风险](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522738&idx=1&sn=39cacf3a0690629e9d07409fb8f9d0d3&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/05/firefox-patches-2-zero-days-exploited.html  
  
  
  
题图：  
Pexels Licen  
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
  
