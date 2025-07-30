#  MOVEit 文件传输软件0day被用于窃取数据   
Eduard Kovacs  代码卫士   2023-06-05 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
**5月31日，Progress Software 提醒称 MOVEit Transfer 管理文件传输 (MFT) 软件受一个严重的SQL注入漏洞影响，可导致未认证攻击者访问 MOVEit Transfer 数据库。**  
  
  
  
  
Progress Software 指出，“根据所使用的数据库引擎（MySQL、Microsoft SQL Server 或 Azure SQL）的不同，攻击者除了能够执行修改或删除数据库元素的 SQL 语句外，还可能能够获取关于数据库结构和内容的信息。”  
  
目前该漏洞的CVE编号正在分配中。  
  
Progress 公司的安全通告有一些歧义，因为该公司表示正在着手推出补丁，但同时列出了应该修复了该漏洞的版本。补丁应当包含在2021.0.6 (13.0.6)、 2021.1.4 (13.1.4)、2022.0.4 (14.0.4)、2022.1.5 (14.1.5) 和 2023.0.1 (15.0.1) 版本中。该产品的云版本似乎也受影响。  
  
该公司的安全公告虽然并未清楚说明该漏洞是否已遭在野利用，但告知客户称打补丁极其重要，并且提供了与相关攻击有关联的妥协指标 (IoCs)。  
  
多家网络安全公司报告称已见到涉及 MOVEit 0day的多起攻击，包括 Huntress、Rapid7、TrustedSec、GreyNoise 和Volexity等。TrustedSec 报道称，大规模利用始于5月28日，攻击者可能利用这一纪念日增加窃取数据的成功率。在这一节假日周末之前也发生了有限的利用。GreyNoise 报道称，与该漏洞相关的扫描活动最早可追溯至3月3日。从最近几天观察到的攻击活动来看，威胁行动者似乎利用该 0day 在 MOVEit 软件的 “wwwroot” 文件夹的 “human2.aspx” 文件中部署了一个 webshell/后门。该后门可导致攻击者获得与 MFT 产品相关的文件和用户列表，下载 MOVEit 中的文件并增加后门管理员用户。  
  
谷歌旗下的 Mandiant 公司一直在调查与该 0day 攻击有关的入侵活动，该公司表示，在过去几天内发现“大规模的利用和广泛的数据盗取活动”。  
  
大型组织机构似乎受影响。目前尚不清楚受影响的组织机构数量，但 Shodan 搜索结果显示约2500个暴露在互联网上的 MOVEit Transfer 实例，该厂商表示其产品用于数万家企业中，其中包括1700家软件厂商。  
  
安全研究员 Kevin Beaumont 提到，其中一个被暴露的 MOVEit 实例似乎属于美国国土安全部 (DHS)。该机构旗下的 CISA 在上周四向组织机构发布提醒。大多数暴露在互联网的实例确实位于美国。攻击者似乎利用该漏洞窃取可能具有价值的数据，这说明攻击的目的可能是勒索性质。如确实如此，则这是近几个越来遭网络犯罪分子攻击的第二款热门 MFT 产品。此前，Fortra 公司的 GoAnywhere 软件漏洞被勒索组织用于窃取很多家组织机构的数据。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[黑客早在2022年10月就利用0day 攻击 Barracuda ESG 设备](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516628&idx=2&sn=eb96b9d65915efbbd1f1b4c2d593f8ee&chksm=ea94b0bedde339a888633e30fcb2b3c54d03a36f0627a8c4fbc37aa593420cfd86fd86d9dbf4&scene=21#wechat_redirect)  
  
  
[利用5个0day的安卓恶意软件 Predator 内部工作原理曝光](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516596&idx=2&sn=7cb9c52c6de509bd244e7ae651a5f1d9&chksm=ea94b0dedde339c84813054bbdbdd547ed52a95f29edf6a134aff5d6417917a6d6f16e49593a&scene=21#wechat_redirect)  
  
  
[Barracuda 邮件网关遭 0day 漏洞利用攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=2&sn=fee108ee4d61523b8dc544a5c1bfd2b8&chksm=ea94b0cedde339d822e3ed4ea277e795e733ad86df5ff4de2e3d1c97f16ea72d051b98a2395c&scene=21#wechat_redirect)  
  
  
[苹果修复3个已遭利用的新 0day](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516531&idx=1&sn=71b3e940c482c53d52c592cdfe3992db&chksm=ea94b019dde3390fb1ecf3bd947eb8852a1f27e29e28f9c88b97d9bb2087840f62be6d882d4b&scene=21#wechat_redirect)  
  
  
[0day 可导致设备遭远程攻陷 贝尔金不打算修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516507&idx=2&sn=4feb9d27621fad108f4bf0e243869f00&chksm=ea94b031dde3392716b432265d80ced2cfbd7405b059e17ff1bc8264c018c4987a6a30fd5e32&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/zero-day-in-moveit-file-transfer-software-exploited-to-steal-data-from-organizations/  
  
  
题图：Pexels License  
  
  
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
  
