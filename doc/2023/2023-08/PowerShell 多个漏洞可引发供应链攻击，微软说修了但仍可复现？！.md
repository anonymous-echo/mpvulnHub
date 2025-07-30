#  PowerShell 多个漏洞可引发供应链攻击，微软说修了但仍可复现？！   
THN  代码卫士   2023-08-18 18:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**PowerShell Gallery 中存在多个漏洞，可触发针对注册表用户的供应链攻击。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSGVvA6EICBns3sQKJibzhSne8IwiauXfEYkrtQOTqYTwHXo7ZIATRhz01Rda5rsSw2tDFL8iaj3XTYQ/640?wx_fmt=png "")  
  
  
Aqua 安全公司的研究员 Mor Weinberger、Yakir Kadkoda和 IIay Goldman 在报告中表示，“这些漏洞导致该注册表中的 typosquatting 攻击的发生不可避免，同时导致用户极其难以识别出程序包的真正所有者。”  
  
PowerShell Gallary 由微软公司维护，是用于分享和获取 PowerShell 代码如 PowerShell 模块、脚本和 DSC 资源的中央仓库。该注册表拥有11,829个唯一报和244,615个程序包。  
  
这些漏洞与该服务对程序包名称的策略不严格有关，缺乏对于 typosquatting 攻击的防御措施，从而导致攻击者上传毫不知情用户认为合法但实际却使恶意的 PowerShell 模块。  
  
Typosquatting 是一种经过检验的感染向量，攻击者通过发布名称类似于通过仓库发布的热门和合法模块类似的包而投毒开源软件生态系统。  
  
第二个缺陷可导致恶意人员嗅探模块的元数据，包括作者、版权和描述字段，使其看似更加合法，从而诱骗不知情用户安装。研究人员支出，“用户判断作者/所有者的唯一方式是打开 ‘Package Details’ 标签。然而，这只会导致用户打开虚假作者的资料，因为攻击者在 PowerShell Gallery 中创建用户时刻自由选择任何名称。因此，判断 PowerShell Gallery 中PowerShell 模块的真正用户是一项艰巨任务。”  
  
第三个漏洞可被滥用于枚举所有的包名称和吧按本，包括未列出的以及无法被公开发现的情况。攻击者可利用 PowerShell API “ https://www.powershellgallery.com/api/v2/Packages?$skip=number”，可导致攻击者获得对完整 PowerShell 包数据库（包括关联版本等）无限制访问权限。  
  
研究人员解释称，“这种不受限制的访问权限可导致恶意人员在未列出程序包中搜索潜在敏感信息，任何未列出的包含敏感数据的程序包都非常容易被攻陷。”  
  
Aqua 公司提到，已在2022年9月将这些弱点告知微软，后者表示在2023年3月7日已推出补丁。然而，这些问题仍然可复现。  
  
研究人员表示，“随着我们对开源项目和注册表的依赖越来越强，与之关联的安全风险也愈加突出。保护用户的责任主要在平台。PowerShell Gallery 以及类似平台有必要采取措施增强其安全性。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信发布《2023中国软件供应链安全分析报告》开源软件供应链的系统化安全治理需加速落地](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517165&idx=1&sn=c9c0c224c7eb021b526c03c079891642&chksm=ea94b287dde33b912cfba6f6ea911ca71a9002d5ca0a6a099ed818f2e235940920185d993340&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[恶意npm包提取开发人员的敏感数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517335&idx=2&sn=6ff43ebd828a02eb665088e4d0c4d46d&chksm=ea94b5fddde33cebc948bf7668dee93f40fa80e2b70a298c0335b79f8a627462c1c958bdc24f&scene=21#wechat_redirect)  
  
  
[NPM生态系统易受 Manifest 混淆攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516873&idx=2&sn=d5ab22c25145dc2fd892d101dc560e1d&chksm=ea94b3a3dde33ab5d80afb71d59329aef641729bb18ec4400c97cc3cebd7df5fbfd464b3f138&scene=21#wechat_redirect)  
  
  
[npm 生态系统遭唯一执行链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516856&idx=2&sn=9e316f8ce6c15221d2febffc55981857&chksm=ea94b3d2dde33ac4bd88eb7de8aac8fea80a949937140741f61eb6f46a9bd01256da8db5a2a7&scene=21#wechat_redirect)  
  
  
[NPM恶意中暗藏恶意软件 TurkoRat](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516557&idx=2&sn=521c7838e15580b71bd43434e2cb49e2&chksm=ea94b0e7dde339f1139bcee9620eb04a5fa5fe9db24596e68169d27eaa8aca481b037affdffb&scene=21#wechat_redirect)  
  
  
[黑客在 NPM 中注入恶意包，发动 DoS 攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516210&idx=1&sn=bd60f2e18839f69eb0c89466bbf57a3e&chksm=ea94b158dde3384ee01e15565842fb64bbd24b04bd07f6dcf316257e6712c4483bf197330c01&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2023/08/experts-uncover-weaknesses-in.html  
  
  
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
  
