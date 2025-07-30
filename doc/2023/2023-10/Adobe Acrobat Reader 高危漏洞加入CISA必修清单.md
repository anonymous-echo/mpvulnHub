#  Adobe Acrobat Reader 高危漏洞加入CISA必修清单   
THN  代码卫士   2023-10-12 18:06  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSokNkofA6fN2xyRrQHialFEO0SqaUiaDWibRBtG206xVy8XKzJvkpRcIjsWXOXlKiahbVXbpSjLonp2Q/640?wx_fmt=gif "")  
  
**美国网络安全和基础设施安全局 (CISA) 将位于 Adboe Acrobat Reader 中的一个高危漏洞加入“已知利用漏洞”分类表，说明已出现活跃利用证据。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSokNkofA6fN2xyRrQHialFEPdYvuBHRlNQSXiaDZp44aibHCvJmxBmxVxnliagSwUTibQwL8JVicc5JIdg/640?wx_fmt=gif "")  
  
  
该漏洞的编号是CVE-2023-21608（CVSS评分7.8），是一个释放后使用漏洞，攻击者以当前用户权限即可实现远程代码执行后果。Adobe 公司在2023年1月发布补丁。该漏洞由 Ashfaq Ansari 和 Krishnakant Patil 发现并报送。  
  
如下版本受影响：  
  
- Acrobat DC - 22.003.20282 (Win)、22.003.20281 (Mac) 和之前版本（在22.003.20310中修复）  
  
- Acrobat Reader DC - 22.003.20282 (Win)、22.003.20281 (Mac) 和之前版本（已在22.003.20310中修复）  
  
- Acrobat 2020 - 20.005.30418 和之前版本（已在20.005.30436中修复）  
  
- Acrobat Reader 2020 - 20.005.30418和之前版本（已在20.005.30436中修复）   
  
  
  
目前尚不清楚滥用CVE-2023-21608的攻击本质以及幕后人员。2023年1月末，该漏洞的POC利用已出现。CVE-2023-21608也是继CVE-2023-26369之后已遭在野利用的第二个Adobe Acrobat 和 Reader 漏洞。CVE-2023-26369是一个界外读漏洞，攻击者可通过打开特殊构造的PDF文档的方式实现代码执行后果。  
  
美国联邦民用行政机构 (FCEB) 被要求在2023年10月31日之前应用由厂商提供的补丁，保护网络免遭潜在威胁。****  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[补丁星期二：微软、Adobe和Firefox纷纷修复已遭利用的 0day 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517643&idx=1&sn=83e85b6b9bf3a9f0cf0c1843c9589950&chksm=ea94b4a1dde33db74b2b9c5ff5da439c9a2169fcab51d215bdc495affe02787d31ab6bcf7b98&scene=21#wechat_redirect)  
  
  
[CISA 将Adobe ColdFusion中的这个严重漏洞列入必修清单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517437&idx=1&sn=561e8ad37f584120784a95e9ad1c33f4&chksm=ea94b597dde33c810a56421fadb562f0a4fbab00589ec4d11a1fb82d61b17dffcab841d4546a&scene=21#wechat_redirect)  
  
  
[CISA紧急提醒：Adobe ColdFusion漏洞已遭在野利用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515947&idx=3&sn=76c36938bf1b7401950fc62730020638&chksm=ea948e41dde30757c6826cbbaeba673c04d191b437bd8a20532e2a13614e94562772ade4c057&scene=21#wechat_redirect)  
  
  
[厂商纷纷主动绕过Adobe发布的CVE-2022-24086安全补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515346&idx=3&sn=7314d6f33c9cc44614100d627ee92de1&chksm=ea948db8dde304aeb1f522231dc8ba2f6cc789d08fd9bc2d2f0964ba7cd303a8233461778c96&scene=21#wechat_redirect)  
  
  
[奥利地公司利用Windows 和 Adobe 0day 攻击欧洲和中美洲实体](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513235&idx=2&sn=24037f6d2d1bec62277ccbb930f55444&chksm=ea9485f9dde30cefdbbe497a8cbe9b23231a2d757bcac7219a0783c35a19d018309cb22bbe8e&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://thehackernews.com/2023/10/us-cybersecurity-agency-warns-of.html  
  
  
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
  
