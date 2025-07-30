#  谷歌修复代码测试工具Bazel 中的严重供应链漏洞   
Stephen Weigand  代码卫士   2024-02-04 18:26  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**谷歌开源的软件开发工具 Bazel 中存在一个严重的供应链漏洞，可导致攻击者插入恶意代码。研究人员指出，该命令注入漏洞影响数百万个依赖于 Bazel 的项目，包括 Kubernetes、Angular、优步、LinkedIn、Dababricks、Dropbox、英伟达和谷歌等。**  
  
  
该漏洞最初由 Cycode 研究团队在去年11月份发现，谷歌在七天内修复。Cycode 研究团队在2月2日披露了漏洞详情。研究员 Elad Pticha 提到，“我们发现，GitHub Actions 工作流中本可被插入恶意代码，原因是 Bazel 的依赖 Actions 中存在一个命令注入漏洞。该漏洞直接影响软件供应链，可导致恶意人员将有害代码插入 Bazel 代码库、创建后门并影响Bazel 用户的生产环境。”  
  
2023年11月1日，研究人员将该漏洞提交给谷歌；11月7日，谷歌审计了该报告并在第二天推出“新提交”更新修复了该漏洞；12月5日，“pull 请求”完全修复了该漏洞；一周后，研究员获得13337美元的漏洞奖励。  
  
  
**漏洞概述**  
  
  
  
  
  
Pticha 写道，谷歌证实了“该漏洞的重要性”。该漏洞的核心与使用GitHub Custom Actions（被称为“一种多功能的”软件开发工作流简化方法）和使用被称为“樱桃采摘”的工作流有关。  
  
根据Atlassian公司的描述，“樱桃采摘”工作流指的是在开发环境中可被引用挑选的任意 Git 提交并附加到当前运行的 HEAD 或代码分支的命令类型。Pticha 写道，“自定义操作可看做代码中被引用的函数，我们使用自己的函数并导入第三方函数。”操作包括 Docker、JavaScript 和 Composite。他写道，“自定义操作位组织机构的软件供应链带来沉重负担。顶层工作流中的数行代码就可被翻译成数千行甚至数百万行代码，其中很多甚至是我们并非发现的。”  
  
研究人员使用 GitHub Actions，设法了解到如何发现命令注入漏洞可针对“摘樱桃”工作流。这些操作使用通过“如 JavaScript 和 Python，并使用多个包管理器如 NPM 或 PyPI 等库，组成庞大的依赖链条。”研究人员设法通过在系统日志中插入恶意 payload的方法获得 Bazel 和 GitHub 的令牌。间接依赖中的漏洞，如自定义操作“难以被发现，因为它们可能位于不同的仓库中、不同的生态系统并由其他维护人员维护。” Pticha 提到，在公开仓库中的340万个工作流中，几乎所有的工作流（约98.75%）都集成了一个或多个操作。  
  
  
****  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[全球软件供应链安全指南和法规概览](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518721&idx=1&sn=a6c98264bc51488064bb51b337094a5c&chksm=ea94bb6bdde3327db988d0cfef1994c2a1fdb66a6ceb2fc1642bb498e3f0c546fa7478db5dc5&scene=21#wechat_redirect)  
  
  
[TensorFlow CI/CD 漏洞使供应链易遭投毒攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518713&idx=1&sn=488228890f80e6cddbaf68f10821849f&chksm=ea94b893dde331854ccef4bfc911cdf55c73813953a87e512b2677a01372974884a061743505&scene=21#wechat_redirect)  
  
  
[软件供应链投毒 — NPM 恶意组件分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518377&idx=1&sn=9504988637a30aee727161562a17cd5a&chksm=ea94b9c3dde330d5c8364a04723d8e973480d0cd285b4ea0da0b9c6d2640ddcadad09ee6bbb1&scene=21#wechat_redirect)  
  
  
[技术提供商遭供应链勒索攻击，逾60家信用社服务宕机](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518271&idx=1&sn=06e13d43d03ff0da28c0310447755248&chksm=ea94b955dde330432570a87f09ab5829e57e3ead7408f781a4549941cb4699b4c1583e8289ca&scene=21#wechat_redirect)  
  
  
[英韩：Lazarus 黑客组织利用安全认证软件 0day 漏洞发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518225&idx=2&sn=0c496ddfdfec8c17e1344333f0c218f6&chksm=ea94b97bdde3306d6bc1249b0087f09b8c0a192157a52d43e8f6b5b08e18465335d8518ce100&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.scmagazine.com/news/supply-chain-vulnerability-fixed-in-google-bazel  
  
  
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
  
