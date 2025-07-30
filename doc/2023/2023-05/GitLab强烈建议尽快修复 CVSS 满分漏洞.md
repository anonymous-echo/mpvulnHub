#  GitLab强烈建议尽快修复 CVSS 满分漏洞   
Bill Toulas  代码卫士   2023-05-25 17:44  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**GitLab 发布紧急安全更新 16.0.1版本，修复CVSS评分为10分的路径遍历漏洞CVE-2023-2825。**  
  
  
  
  
GitlAB 是基于 web 的 Git 仓库，为需要远程管理代码的开发团队服务，目前已拥有约3000万名已注册用户以及100万名付费客户。该漏洞由研究员  pwnie 发现并提交给 HackerOne 平台。  
  
CVE-2023-2825虽然影响 GitLab 社区版 (CE) 和企业版 (EE) 16.0.0，但低于该版本的所有版本均不受影响。该漏洞是由路径遍历问题引发的。当附件存在于至少五个组的公开项目时，可导致未认证攻击者读取服务器上的任意文件。  
  
利用该漏洞可暴露敏感数据，包括专有软件代码、用户凭据、令牌、文件和其它私密信息。这些前提说明该漏洞与 GitLab 如何管理或解决所附文件路径有关。然而，鉴于该漏洞的严重性以及披露的时效性，GitLab 并未透露更多详情。  
  
GitLab 强调了立即应用最新安全更新的重要性。GitLab 在安全公告中提到，“我们强烈建议所有运行受如下这些漏洞影响版本的程序，尽快升级至最新版本。如未提到特定的部署版本，则意味着所有类型均受影响。”  
  
一个缓解因素是，该漏洞仅可在特定条件下被触发，即当嵌入至少五个组的某个公开项目中存在附件时就会被触发，并非所有的 GitHub 项目都遵循这种结构。尽管如此，建议所有的 GitLab 16.0.0用户尽快升级至16.0.1。遗憾的是，目前并不存在缓解措施。  
  
要更新 GitLab 版本，可遵循该项目的更新页面指南。对于 GitLab Runner 更新，可按照相关更新操作。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[GitLab修复GitHub import函数中的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514207&idx=1&sn=eda12473aec122dcbe50bf0b2545da32&chksm=ea948935dde300234feefd9ebdb2e36056f43a607bd274323e86088fbc98d2737efa2f63658f&scene=21#wechat_redirect)  
  
  
[GitLab 远程代码执行漏洞安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513707&idx=1&sn=6c80379607fc2214bebf651c01750491&chksm=ea948701dde30e17d699dd8ce24dd9852b091e66462aee72c89a53dae49d8d3027bb1ddb3c99&scene=21#wechat_redirect)  
  
  
[GitLab 修复两个严重的远程代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513659&idx=2&sn=2f2dfa5beb36144d258cfc9aae9a6961&chksm=ea948751dde30e47c001f82da2a744dd9248717d7d94b35de8b94974f3fa361b8b3dfe6effc5&scene=21#wechat_redirect)  
  
  
[GitLab 修复严重的RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512696&idx=3&sn=28d8f32cf57de253821034371b037814&chksm=ea948312dde30a0443b57c1103f2a160c6d272166ec1c295bbeebcfcb447959e8e3a1e91c6db&scene=21#wechat_redirect)  
  
  
[GitLab 企业版修复严重的账户接管漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512136&idx=2&sn=7edd2c1fb3ff99f84a690b13cdaf4187&chksm=ea948122dde30834d5fdb08d5dbfe867400f3291ab4a1d5f74d90de59542e04e1114691012b4&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/gitlab-strongly-recommends-patching-max-severity-flaw-asap/  
  
  
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
  
