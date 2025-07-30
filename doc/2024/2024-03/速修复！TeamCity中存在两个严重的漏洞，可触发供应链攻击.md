#  速修复！TeamCity中存在两个严重的漏洞，可触发供应链攻击   
Zeljka Zorz  代码卫士   2024-03-05 17:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**JetBrians 修复了影响 TeamCity本地版的两个严重漏洞（CVE-2024-27198和CVE-2024-27199），督促客户立即打补丁。**  
  
  
JetBrians 公司表示，“Rapid7 公司最初发现并将这些漏洞告知我们，并严格遵守自己的漏洞披露策略。这意味着他们的团队将在本通知发布的24小时内，公开这些漏洞的完整技术详情及其复现过程。”  
  
这也意味着PoC和完整 exploit 也将很快浮出水面并遭利用。而实际上在文本发布时漏洞详情已发布。  
  
  
**漏洞简述**  
  
  
  
  
  
  
JetBrians 创建的 TemCity 是持续集成和持续交付 (CI/CD) 服务器，其中包含的漏洞最近遭俄罗斯和朝鲜国家黑客的利用。  
  
CVE-2024-27198和CVE-2024-27199可能允许攻击者实现绕过认证，通过使用可选路径或信道 (CWE-288) 和遍历文件系统，访问受限制的目录以外的文件/目录 (CWE-23)。该公司提醒称，“这些漏洞可导致具有对 TeamCity 服务器 HTTP(S) 访问权限的未认证攻击者绕过认证检查并获得对TeamCity服务器的管理员控制权限。”  
  
CVE-2024-27198 可允许远程未认证攻击者攻陷易受攻击的 TeamCity 服务器并获得对所有与服务器存在关联的项目、构建、代理和工件的控制，方法是创建新的管理员用户或者生成新的管理员访问令牌。这就使得该漏洞成为发动供应链攻击的理想漏洞。  
  
CVE-2024-27199可允许数量有限的信息披露和系统修改，包括未认证攻击者可替代易受攻击 TeamCity 服务器中的HTTPS证书。攻击者可修改HTTP端口号或上传无法通过客户端验证的证书，发动DoS攻击。或者，在网络具有适当位置的攻击者能够在客户端连接上执行窃听或中间人攻击，前提是攻击者所上传的证书（并具有私钥）获得客户端的信任。  
  
  
**更新、打补丁或服务器断网**  
  
  
  
  
  
这两个漏洞影响TeamCity本地2023.11.3所有版本，并已在2023.11.4版本中修复。JetBrains公司表示，“TeamCity Cloud 服务器已打补丁，我们已验证它们并未遭攻击。”  
  
该公司客户升级至已修复版本（手动或自动修复）；如无法升级至v2023，则应用安全补丁插件（兼容TeamCity 所有版本）；如服务器可从互联网公开访问且无法立即应用缓解措施，则建议客户先将服务器断网。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复代码测试工具Bazel 中的严重供应链漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518821&idx=1&sn=8a1a67b87d1bbad6e1c80390fe7c1c61&chksm=ea94bb0fdde33219950ecb20753f8d0ab99b42fbe0e84141e12196184450ccbc041a602bc10b&scene=21#wechat_redirect)  
  
  
[全球软件供应链安全指南和法规概览](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518721&idx=1&sn=a6c98264bc51488064bb51b337094a5c&chksm=ea94bb6bdde3327db988d0cfef1994c2a1fdb66a6ceb2fc1642bb498e3f0c546fa7478db5dc5&scene=21#wechat_redirect)  
  
  
[TensorFlow CI/CD 漏洞使供应链易遭投毒攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518713&idx=1&sn=488228890f80e6cddbaf68f10821849f&chksm=ea94b893dde331854ccef4bfc911cdf55c73813953a87e512b2677a01372974884a061743505&scene=21#wechat_redirect)  
  
  
[软件供应链投毒 — NPM 恶意组件分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518377&idx=1&sn=9504988637a30aee727161562a17cd5a&chksm=ea94b9c3dde330d5c8364a04723d8e973480d0cd285b4ea0da0b9c6d2640ddcadad09ee6bbb1&scene=21#wechat_redirect)  
  
  
[技术提供商遭供应链勒索攻击，逾60家信用社服务宕机](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518271&idx=1&sn=06e13d43d03ff0da28c0310447755248&chksm=ea94b955dde330432570a87f09ab5829e57e3ead7408f781a4549941cb4699b4c1583e8289ca&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://www.helpnetsecurity.com/2024/03/04/cve-2024-27198-cve-2024-27199/  
  
  
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
  
