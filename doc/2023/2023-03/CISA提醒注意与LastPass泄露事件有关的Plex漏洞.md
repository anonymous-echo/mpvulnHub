#  CISA提醒注意与LastPass泄露事件有关的Plex漏洞   
Ionut Arghire  代码卫士   2023-03-14 17:53  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTNe8aQJNdzWPhAAqvKBpa4icIp1xLaHDbYv29n3O7gricY7EEORkfL1eSlibuSBUPTBO7y8Lm2946VA/640?wx_fmt=png "")  
  
  
**美国网络安全和基础设施安全局 (CISA) 在“已知利用漏洞 (KEV)”分类列表中新增了影响Plex和VMware产品的漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTNe8aQJNdzWPhAAqvKBpa4PppQI3TLyPLoFm9wSaOA2mDaibXpFU4ObaHxOxbXo2amctYUD7xp4Mg/640?wx_fmt=png "")  
  
  
CVE-2020-5741是位于Plex Media Server中的一个高危反序列化漏洞，可悲用于远程执行任意Python代码。Plex 公司在2020年5月的一份安全公告中提到，“该漏洞可导致能够访问服务器管理员Plex账户的攻击者通过Camera Upload特性上传恶意文件，并使媒体服务器执行。”该漏洞已在 Plex Media Server 1.19.3中修复，要求攻击者需要具有对Plex Media Server具有管理员访问权限才能实施成功利用，从而使其难以用于攻击中。  
  
不过，Plex 在2022年8月披露一起数据泄露事件称，该漏洞影响超过1500万名客户，导致用户名、邮件和密码数据被盗。这就导致未修复的Plex Media Server实例仍然受影响。  
  
虽然CISA并未共享关于在野利用的详情，但最近发布的媒体报道表明，去年发生的LastPass数据泄露事件可能与Plex漏洞被用于入侵DevOps工程师的计算机有关。  
  
Plex 回应称，该公司严肃对待安全问题，并设立安全指南和漏洞奖励计划与外部合作。该公司提到从未发布未修复的漏洞情况，并非发现未修复漏洞遭公开的情况。另外，该公司从LastPass获悉该漏洞已遭利用，Plex在2020年5月份公开该漏洞详情。当时，Plex公司已发布修复版本，但LastPass并未激活补丁。Plex 公司将通过管理员UI发布关于更新的相关情况。  
  
CISA还新增了另外一个漏洞，即位于XStream 中的远程代码执行漏洞CVE-2021-39144，该漏洞被指用于攻击VMware 产品。该漏洞影响VMware Cloud Foundation 和 NSX Data Center for vSphere。CISA提到，“该漏洞影响多款产品，包括但不仅限于VMware Cloud Foundation。”  
  
根据BOD 22-01的要求，联邦机构需要在3月31日前修复这些漏洞。不过建议所有机构查看该分类表并应用必要补丁。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[CISA必修列表未收录数十个已遭利用漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515885&idx=2&sn=26d62bc99cdd37f8365bae8a9b94dba5&chksm=ea948f87dde30691fa7f9887c40e755916adb1ef81c320c67bd9cf032e3495edbc2c16f71288&scene=21#wechat_redirect)  
  
  
[CISA新增3个影响IT管理系统的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515862&idx=3&sn=e59b1a83fa85ee490560066b8b39f535&chksm=ea948fbcdde306aa8791fa944d0c5db86f2535cd2381fc0dcc7d846cf5ee4c1686e12f3696d8&scene=21#wechat_redirect)  
  
  
[CISA 提醒称黑客正在利用 ZK Java 框架中的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515787&idx=2&sn=833c589738704d28969098a2ddf6b07c&chksm=ea948fe1dde306f765bcebafffd6d83e25e7e661b2d28f2736104a8b44fdda955a5cd746552d&scene=21#wechat_redirect)  
  
  
[美国CISA将设立供应链风险管理办公室](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515460&idx=3&sn=e88c34df75275d13d1331d4c0714279e&chksm=ea948c2edde305385fc20864a696ea25c625a2e5604742d8d4cd5026ba6afa9d2223e94cf431&scene=21#wechat_redirect)  
  
  
[CISA提醒注意西门子、通用数字和康泰克工控系统中的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515346&idx=2&sn=9c64d78059c7b3ee275ab9039c5b3544&chksm=ea948db8dde304aeca214fe6e90ce53733d06ee853e596d44400020349aeb9c8fd6ab433bba3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.securityweek.com/cisa-warns-of-plex-vulnerability-linked-to-lastpass-hack/  
  
  
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
  
