#  GitLab 严重漏洞导致攻击者以任意用户身份运行管道   
Bill Toulas  代码卫士   2024-06-28 17:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSRSoqqgwHrsPicxARzaB6TMIx7un9sljs1Dxb7xgO2x1reApNFCNfNFIhoOZNk2cOrW9zu04xcmvg/640?wx_fmt=gif&from=appmsg "")  
  
**GitLab 社区版和企业版的某些版本受一个严重漏洞 (CVE-2024-5655) 影响，可被攻击者用于以任何用户身份运行管道。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSRSoqqgwHrsPicxARzaB6TMsPFlNBQLNw1OGuTEoPkZlsrjOpicfxSslmLFicOo9Z141WI03V60mGPg/640?wx_fmt=gif&from=appmsg "")  
  
  
GitLab 是一款基于 web 的热门开源软件项目管理和工作跟踪平台，活跃的许可用户数量约100万人。该漏洞的CVSS评分为9.6，在一定条件下可被攻击者以其它用户身份触发管道。  
  
GitLab 管道是CI/CD系统的一个特性，可使用户平行或按顺序自动运行进程和任务，构建、测试或部署代码变更。  
  
该漏洞影响15.8至16.11.4、17.0.0到17.0.2以及17.1.0到17.1.0的所有 GitLab 社区版/企业版版本。GitLab 提到，“我们强烈建议运行受影响版本的安装程序尽快升级至最新版本。”  
  
GitLab 已发布17.1.1、17.0.3和16.11.5版本修复该漏洞，并建议用户尽快应用这些更新。GitLab 还提到升级到最新版本需要注意其中的两个重大变化：  
  
- 之前的目标分支被合并后，如果合并请求被重新针对，则管道将不再自动运行。用户必须手动启动管道，执行这些变更的CI。  
  
- 从17.0.0版本开始，GraphQL认证将默认禁用 CI_JOB_TOKEN，这一变更回滚到了版本 17.0.3和16.11.5。要访问 GraphQL API，用户应对受支持的令牌类型之一进行认证配置。  
  
  
  
最新的GitLab 更新还包括对13个其它漏洞的修复，其中3个被评级为“高危”（CVSS v3.1评分7.5-8.7），如下：  
  
- CVE-2024-4901：存储型XSS漏洞，可导致导入项目的恶意提交说明注入脚本，可能导致越权操作和数据暴露。  
  
- CVE-2024-4994：位于 GraphQL API中的CSRF漏洞，可导致攻击者诱骗认证用户提出不必要的请求执行任意 GraphQL 变化，可能导致数据操纵和越权操作。  
  
- CVE-2024-6323：位于 GitLab 全局搜索特性中的授权漏洞，可导致攻击者在公开项目的私密仓库中搜索结果，可能导致信息泄露和越权访问敏感数据。  
  
  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab 高危漏洞可导致账号遭接管](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519584&idx=1&sn=8ca7ba7442a6234b2f5910147094c5bb&chksm=ea94bc0adde3351ccee634db2e180e9bc4d66ff43d4aa7e08ca703c79df1444bcf27d1b960de&scene=21#wechat_redirect)  
  
  
[GitLab 提醒注意严重的零点击账户劫持漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518669&idx=1&sn=e9e78678e6c35cd6c0c37b638d5a988c&chksm=ea94b8a7dde331b16bdf8306a2700a04ea240bc5baa204b72ab3c9664a58b77c6fc92b1841f4&scene=21#wechat_redirect)  
  
  
[GitLab 督促用户安装安全更新，修复严重的管道漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517701&idx=2&sn=9efeb89e9c34a3dcb192e347897ea5d3&chksm=ea94b76fdde33e79439751b5f121c7f1c6903963de1ec1e650ed19876271b10ebc9271391861&scene=21#wechat_redirect)  
  
  
[GitLab强烈建议尽快修复 CVSS 满分漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516580&idx=1&sn=3e272b8a4ba9c8f7b596e5bc1c9f6576&chksm=ea94b0cedde339d8dee6f14566aaa4da84cb44e202cc0582353695ecd4620c832ba4c9ddab91&scene=21#wechat_redirect)  
  
  
[GitLab修复GitHub import函数中的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514207&idx=1&sn=eda12473aec122dcbe50bf0b2545da32&chksm=ea948935dde300234feefd9ebdb2e36056f43a607bd274323e86088fbc98d2737efa2f63658f&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/critical-gitlab-bug-lets-attackers-run-pipelines-as-any-user/  
  
  
题图：  
Pexels  
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
  
