#  Apache Linkis 修复多个漏洞   
DO SON  代码卫士   2023-04-13 17:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Apache Linkis 是一款热门的计算中间件，用于弥合上层应用程序和底层引擎之间的差距，从而能够无缝访问多个引擎如 MySQL、Spark、Hive、Presto 和 Flink。然而，研究人员在 Apache Linkis 中发现多个需要解决的重要漏洞，以确保用户数据和系统的持续安全性和完整性。**  
  
**CVE-2023-27602**是位于 Apache Linkis PublicService 模块中的不受限文件上传漏洞，影响1.3.1及之前版本。该漏洞可用于攻陷用户系统的完整性。建议用户升级至Apache Linkis 1.3.2版本，修复该漏洞。对于1.3.1及之前版本，用户应通过如下设置，启动 linkis.properties 文件中的文件路径检查：  
  
wds.linkis.workspace.filesystem.owner.check=true  
  
wds.linkis.workspace.filesystem.path.check=true  
  
**CVE-2023-27603** 是位于Apache Linkis Manager 模块中的 Zip Slip 漏洞，影响1.3.1及之前版本，产生的原因是 engineConn 物料上传中缺少正确的 zip 路径检查造成的，可能导致远程代码执行漏洞。为缓解该漏洞，建议用户升级至 Apache Linkis 版本1.3.2。  
  
**CVE-2023-29215**是位于 Apache Linkis JDBC EngineConn 中的反序列化命令执行漏洞，影响1.3.1及之前版本，产生原因是参数过滤不足。攻击者可利用该漏洞获得远程代码执行能力。为缓解该漏洞，用户应升级至 Apache Linkis 1.3.2 版本。  
  
**CVE-2023-29216**是存在于 Apache Linkis DatasourceManager 模块中的反序列化命令执行漏洞，影响1.3.1及之前版本，是由于对 DatasourceManager 模块中的参数过滤不充分造成的，可导致攻击者使用恶意 MySQL 数据源和参数触发反序列化漏洞，从而导致远程代码执行后果。用户应升级至 Apache Linkis 版本1.3.2，缓解该漏洞。  
  
**CVE-2023-27987**是位于 Aapche Linkis Gateway 模块中的令牌验证绕过漏洞，影响1.3.1及之前版本，是由 Linkis Gateway 部署所生成的默认令牌太过于简化造成的，导致攻击者易于获取并利用默认令牌。用户应升级至 Apache Linkis 1.3.2版本并修改默认令牌值，缓解漏洞。  
  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[【已复现】Apache Kafka Connect JNDI注入漏洞(CVE-2023-25194)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515512&idx=2&sn=e98e47bd34da117cc9f366253220df47&chksm=ea948c12dde30504b800504eae806ba06d26ac8b0598b1bc3e9808c2574a3161a52d5a6e6edf&scene=21#wechat_redirect)  
  
  
[Apache Superset中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515321&idx=1&sn=4a78d9a57c0023b7b411bfdfd7ad2685&chksm=ea948dd3dde304c5d44d1b6bc680eb189e446a4283f43ff18d0b7adbf8844360d7e20af86e7f&scene=21#wechat_redirect)  
  
  
[Apache ShardingSphere身份认证绕过漏洞(CVE-2022-45347)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515110&idx=1&sn=10da0adc762309a9618737f6e904f5fa&chksm=ea948a8cdde3039a022c5f4a87205395353bc885de41fca990d6d25193688fbce21bc604375a&scene=21#wechat_redirect)  
  
  
[速修复！Apache Commons Text 存在严重漏洞，堪比Log4Shell](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514246&idx=1&sn=05c9cf544ef37daf01a04001b22b2584&chksm=ea9489ecdde300fae250e9a720d8fb6ccb7704229f946b796c6aec685c3e6a9446169ec5ad12&scene=21#wechat_redirect)  
  
  
[Apache开源项目 Xalan-J 整数截断可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513963&idx=4&sn=8f7f84190a33593bda1e3d6c86470af6&chksm=ea948601dde30f178f02bdcc42ac15f052526722f31417ec3cc51f2b92cde6a84be7894c8fe8&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://securityonline.info/apache-linkis-patched-several-important-security-vulnerabilities/  
  
  
题图：Pixabay License  
  
  
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
  
