#  Django 修复SQL注入漏洞   
Ax Sharma  代码卫士   2022-07-05 18:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
Django 项目是基于 Python 的开源 web框架，近期它修复了位于最新版本中的一个高危漏洞CVE-2022-34265。  
  
  
该漏洞是存在于 Django 主分支4.1（目前处于测试）、4.0和3.2中的一个SQL注入漏洞，目前已修复。  
  
数万个网站，其中包括美国的很多流行品牌，选择 Django 作为 Model-Template-View 框架，而这就是为何需要升级或修复Django实例非常重要的原因所在。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRv6dVMBB6ZgFXrc3gJYh2xIbJqOo3lYgLLricCvwrNStZrGZnSTC3SAjqZDv36g4ZCkZP0WQxlDxw/640?wx_fmt=gif "")  
  
**新版本缓解潜在的SQL注入漏洞**  
  
  
  
Django 团队发布版本4.0.6和3.2.14 解决了该高危SQL漏洞，并督促开发人员尽快升级或修复 Django 实例。该漏洞可导致攻击者通过向 Trune(kind) 和 Extract (lookup_name) 函数的参数攻击 Django web 应用。  
  
Django 发布安全公告指出，“如果将不受信任数据用作kind/lookup_Name 值，则Trunc() 和 Extract() 数据库函数受SQL注入漏洞影响。将lookup name 和 kind 选择先知道已知的安全列表的应用程序不受影响。”换句话说，如果应用程序在将这些参数传递给 Trunc 和 Extract 函数之前执行了某种输入清理或逃逸，则不受影响。  
  
该漏洞是由 Aeye安全实验室的研究员 Takuto Yoshikai 发现并报告的。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMRv6dVMBB6ZgFXrc3gJYh2xIbJqOo3lYgLLricCvwrNStZrGZnSTC3SAjqZDv36g4ZCkZP0WQxlDxw/640?wx_fmt=gif "")  
  
**补丁已发布**  
  
  
  
对于无法升级到已修复Django 版本4.0.6或3.2.14的用户，Django 团队已推出可应用到已有的受影响版本的补丁。  
  
Django 团队表示，虽然安全发布缓解了该漏洞，但发现可以改进 Database API 方法。这种情况将影响使用 Django 4.1 发布候选版本1或更新版本的第三方数据库后端，更新至API变更之后才会解决。  
  
Django 的安全策略指出，可向security@djangoproject.com 反馈遇到的任何潜在安全问题。  
  
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
