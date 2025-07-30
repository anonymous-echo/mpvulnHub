#  Apache Superset 会话验证漏洞可导致攻击者访问未授权资源   
Thomas Claburn  代码卫士   2023-04-26 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**今年年初早些时候，Apache Superset 中设置了不安全的默认配置，攻击者可借此登录并接管该数据可视化应用、窃取数据并执行恶意代码。该漏洞编号是CVE-2023-27524。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMT01Op6m7ufib1jSxtwyykBjkzuBpTibmcIkHicibDIEv5c1C8DDdjCb1F6yEwczEKN6PoibIG7eoeviarg/640?wx_fmt=gif "")  
  
  
Apache Superset 基于 Python 的Flash 框架，默认配置公开已知的密钥 SECRET_KEY = '\2\1thisismyscretkey\1\2\e\y\y\h'。  
  
安全公司 Horizon3.ai 发布安全公告解释称，当用户登录 Superset 实例时，该 web 应用将带有用户标识符的会话 cookie 发回给访客的 web 浏览器中。Horizon3.ai 公司的首席架构师 Naveen Sunkavally 指出，“该 web 应用通过 SECRET_KEY 签名该 cookie，而该值是随机生成的且一般存储在本地配置文件中。”如果攻击者了解 SECRET_KEY 的值，则可生成并签名 cookie，从而以应用管理员身份进行认证。通过名为 flask-unsign 的工具检查 Superset 是否使用默认密钥非常容易。  
  
Sunkavally 指出，约三分之二的 Superset 用户在设置 Superset 时并未生成新的密钥：截止2021年10月11日，该应用约3000个实例被暴露在互联网上，其中2000个实例依赖的是默认的密钥。  
  
Apache 安全团队在第二天回复，2022年1月11日做出了一些变更，并设立了新的默认密钥："CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET"。但这次该 app 中包含了检查该新的默认密钥是否变更的功能。如未变更，该 app 将在日志文件中发出提醒并给出如何生成安全密钥的指南。然而，该提醒是否能够引起注意，则取决于用户。  
  
就在这次变更过去了一年多的时间后，2023年2月9日，Horizon3.ai 公司再次检查有多少 Superset 实例配置了公开的默认密钥。这次他们还将 Shodan.io 搜索扩展到四种不同的默认密钥中：原始密钥、新密钥以及来自部署模板以及来自文档的密钥。  
  
结果发现，情况没有太多改变。在3176个Superset 实例中，2124个（约67%）使用了其中一种默认密钥。  
  
于是，Horizon.ai 团队再次联系 Apache 安全团队。两周后即2023年2月24日，该项目维护人员发布更新作为4月5日2.1版本发布的一部分，“当发现默认 SECRET_KEY时，应采取更坚决的措施。”该变更的目的是让 app 不使用默认密钥。  
  
Sunkavally 指出，“通过这次更新，很多 Superset 的新用户将不再无意识地中招。”他提醒称，如果该软件是通过 docker-compose 文件或 helm 模板安装的话，则仍然可能导致使用不安全的 Superset 版本。他提到，“ docker-compose 文件中包含 TEST_NON_DEV_SECRET 的新的默认 SECRET_KEY，我们认为某些用户将不知不觉地运行。某些配置还将 admin/admin 设置为管理员用户的默认凭据。”  
  
该漏洞的编号为CVE-2023-27524。Sunkavally 表示，受影响的用户可通过依赖于 flask-unsign 的脚本查看自己的服务器中含有默认密钥。所识别出的2000多个易受攻击的 Superset 实例由大小规模的企业、政府机构和大学运营。Sunkavally 还提到这些组织机构在收到通知后修复了该漏洞。  
  
Sunkavally 认为，这一事件表明用户未阅读文档且未阅读日志。他提到，“最佳方式是不要把选择权交给用户，而是要求他们采取安全措施。”  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQZeSribxs2yU1w56EMvgX9cDBCiabniazxdxtQ25cBCAd5vBJIM2sOv1khjzwwViaT0pS74U6piaiauiaGA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Apache Linkis 修复多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516234&idx=1&sn=ba72ac437de85dff898598d11ce97f6d&chksm=ea94b120dde338367ba09290193fddc80c82805257f0aac35587dafcb63dd98f43f418cc767f&scene=21#wechat_redirect)  
  
  
[【已复现】Apache Kafka Connect JNDI注入漏洞(CVE-2023-25194)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515512&idx=2&sn=e98e47bd34da117cc9f366253220df47&chksm=ea948c12dde30504b800504eae806ba06d26ac8b0598b1bc3e9808c2574a3161a52d5a6e6edf&scene=21#wechat_redirect)  
  
  
[Apache Superset中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515321&idx=1&sn=4a78d9a57c0023b7b411bfdfd7ad2685&chksm=ea948dd3dde304c5d44d1b6bc680eb189e446a4283f43ff18d0b7adbf8844360d7e20af86e7f&scene=21#wechat_redirect)  
  
  
[Apache ShardingSphere身份认证绕过漏洞(CVE-2022-45347)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515110&idx=1&sn=10da0adc762309a9618737f6e904f5fa&chksm=ea948a8cdde3039a022c5f4a87205395353bc885de41fca990d6d25193688fbce21bc604375a&scene=21#wechat_redirect)  
  
  
[速修复！Apache Commons Text 存在严重漏洞，堪比Log4Shell](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514246&idx=1&sn=05c9cf544ef37daf01a04001b22b2584&chksm=ea9489ecdde300fae250e9a720d8fb6ccb7704229f946b796c6aec685c3e6a9446169ec5ad12&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.theregister.com/2023/04/25/apache_superset_cve/  
  
  
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
  
