#  Atlassian 修复Jira 中的完全读取SSRF漏洞   
Adam Bannister  代码卫士   2022-07-07 18:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Atlassian 公司的热门问题追踪和项目管理软件 Jira 易受一个服务器端请求伪造 (SSRF) 缺陷影响，在无需凭据的情况下即可遭滥用。**  
  
  
Assetnote 公司的首席技术官兼创始人 Shubham Shah 在博客文章中指出，“根据Jira 实例的不同，有很多种方法可以在 Jira 上创建账户来利用该漏洞”，例如滥用 Jira Service Desk 的签名功能，该功能常常启用以提供自助服务机制。Shah 表示，“首先在 Jira Service Desk 上注册，然后使用这个账户访问 Jira Core REST APIs，即可成功利用该认证后漏洞。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAn9ibvpN9EniaJ2e72CSNLUOC6yfqRd0HoyxUTunBsicCmouH9IHEXDbOJtoFM9Gvg5fNlcs7H4J9w/640?wx_fmt=gif "")  
  
**多种影响**  
  
  
  
该漏洞的编号为CVE-2022-26135，是位于Jira Server Core 中的完全读取SSRF漏洞，“可导致攻击者通过任何HTTP方法、标头和主体向任意URL提出请求”。  
  
该漏洞影响与 Jira 以及 Jira Service Management 绑定的Jira Mobile Plugin 中使用的批量HTTP 端点。Atlassian 公司发布安全公告指出，“可以通过易受攻击端点主体中的方法参数控制HTTP方法和URL位置。根据Jira 实例所部署的环境的不同，该漏洞的影响各不相同。例如，如果部署在AWS中，则可能泄露敏感凭据。”  
  
研究人员通过PoC exploit 在Jira Core 或 Jira Service Desk 上创建账户，之后自动利用该SSRF漏洞。研究人员在4月21日将漏洞告知 Atlassian 公司的安全团队，后者在6月29日推出补丁。  
  
Jira 和 Jira Service Management 所有之前的版本均受影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRAn9ibvpN9EniaJ2e72CSNLUOC6yfqRd0HoyxUTunBsicCmouH9IHEXDbOJtoFM9Gvg5fNlcs7H4J9w/640?wx_fmt=gif "")  
  
**研究经验**  
  
  
  
研究人员逆向2022年4月披露的Seraph 中的认证绕过漏洞补丁后发现了该SSRF漏洞。该认证绕过漏洞也影响 Jira Mobile Plugin。  
  
Shah 指出，“评估厂商安全公告、补丁并逆向受影响组件有时会发现新的漏洞。”他还建议其他研究员，“即使无法通过漏洞来绕过认证，但可考虑该应用程序和功能的完整上下文来判断利用从认证后攻击面中发现的漏洞的其它方法。”  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[多款 Django 应用配置不当  泄露API 密钥数据库密码等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486789&idx=2&sn=521763a8289868668f2e22b4e2850860&chksm=ea973c2fdde0b539db8142f6b3df26fd818614c29a33504e3ef1125ea66fa0e6acb96da743dd&scene=21#wechat_redirect)  
  
  
[史无前例：微软 SQL Server 被黑客组织安上了后门 skip-2.0（来看技术详情）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247491335&idx=1&sn=a605c33af49378abcaffe800b4455c88&chksm=ea972e6ddde0a77bae4e45bd81123099bc64c3dd512767351e7e595f4010a204feb8d37c79be&scene=21#wechat_redirect)  
  
  
[Sophos 修复 Cyberoam OS 中的 SQL 注入漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247498802&idx=2&sn=f481361fa7963f4f1b2b9a57c5c54312&chksm=ea94cd58dde3444e44870fd2833121c992e9af3d635031e84e710f039940f1f713a62f5022cd&scene=21#wechat_redirect)  
  
  
[看我如何绕过Cloudflare 的 SQL 注入过滤](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247495128&idx=1&sn=f57fc6d8dfcfd3b900224c2a3dbaa0a0&chksm=ea94dcb2dde355a429a91ec3ad5d0138cac297dad4dc574638670b4b3db0d645b156bd9e712a&scene=21#wechat_redirect)  
  
  
[看我如何在星巴克企业数据库找到影响百万用户的SQL注入漏洞并赢得最高赏金](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490560&idx=1&sn=81bc1c1eca2b458a2b36fd9cca464494&chksm=ea972d6adde0a47cd27c52a5b418db612277245287d2d1484dce61a7353abc4452927f2f7f39&scene=21#wechat_redirect)  
  
  
[【缺陷周话】第 2 期 ：SQL 注入](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247488076&idx=1&sn=3101e6e5a7285c7f71a5f04e78f90709&chksm=ea972326dde0aa30ce0137e0996a536f51e6e2d23eb2a31aac3cdb47c342ff9672baf8699a1b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/django-fixes-sql-injection-vulnerability-in-new-releases/  
  
  
题图：  
Pixabay License  
  
  
  
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
