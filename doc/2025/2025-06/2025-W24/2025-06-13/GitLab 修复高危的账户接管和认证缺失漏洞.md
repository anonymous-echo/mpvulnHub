> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523281&idx=1&sn=39fe6b4ec8cebc0a362c26c8fffbd2c7

#  GitLab 修复高危的账户接管和认证缺失漏洞  
Sergiu Gatlan  代码卫士   2025-06-13 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**GitLab 发布安全更新，修复了该公司 DevSecOps 平台中的多个漏洞，其中一些可导致攻击者接管账户并在未来的管道中注入恶意任务。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRV4TpHia5020fSlxqurOMJeyG88q4OfM02iapvB5icwRib9E4o3hWcRn2JrtJH6DDnGn3Wtu7SfTSgow/640?wx_fmt=png&from=appmsg "")  
  
  
GitLab 发布GitLab 社区版和企业版18.0.2、17.11.4和17.10.8，修复了这些漏洞并督促所有管理员立即升级。该公司提醒称，“这些版本中包含重要的漏洞和安全修复方案，我们强烈建议所有的自管理 GitLab 立即升级至这些版本。GitLab.com已运行已修复版本。GitLab Dedicated 客户无需采取任何措施。”  
  
本周三，GitLab 修复了一个HTML注入漏洞CVE-2025-4278，它可导致远程攻击者将恶意代码注入搜索页面，接管账户。GitLab 还发布了影响 GitLab Ultimate EE的授权缺失问题CVE-2025-5121，它可导致远程威胁人员将恶意CI/CD任务注入任何项目的未来CI/CD管道中。  
  
GitLab 管道是一个CI/CD系统特性，可使用户按序构建、测试或部署代码变更或平行自动运行进程和任务。然而，成功利用该漏洞要求攻击者对具有 GitLab Ultimate 许可证的 GitLab 实例拥有认证权限。  
  
GitLab 公司还修复了一个XSS漏洞CVE-2025-2254（可导致攻击者在合法用户的上下文中执行任何操作）和一个DoS 漏洞CVE-2025-0673（可导致恶意人员触发无限的重定向循环，导致内存耗尽和合法用户拒绝访问）。  
  
GitLab 仓库中包含敏感信息和数据，因此常常成为被攻击的目标。最近跨国汽车租赁公司 Europcar Mobility Group和教育巨头Pearson 的 GitLab 仓库自去年年初开始就被攻陷。  
  
GitLab 的DevSecOps 平台拥有3000多万名注册用户，用于超过50%的财富100强公司，如高盛、Airbus、T-Mobile、Lockheed Martin、英伟达和UBS等。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab Duo 漏洞可导致攻击者通过隐藏的提示劫持AI响应](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=2&sn=11426f6aaac01c747218a552ac6e5129&scene=21#wechat_redirect)  
  
  
[GitLab：注意严重的任意分支管道执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521035&idx=1&sn=2551f0b914e44081d01813a9f39a47c4&scene=21#wechat_redirect)  
  
  
[GitLab修复严重的 SAML 认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520856&idx=1&sn=99796b9ba1361fcd9611a05729e2219d&scene=21#wechat_redirect)  
  
  
[GitLab 提醒注意严重的管道执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520799&idx=1&sn=2e34312c9e5c05291452bf69189cd8b5&scene=21#wechat_redirect)  
  
  
[GitLab 又爆新的CI/CD管道接管漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520065&idx=2&sn=2dfd0b72bc28e69fa94a19fdb4828ace&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/gitlab-patches-high-severity-account-takeover-missing-auth-issues  
/  
  
  
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
  
