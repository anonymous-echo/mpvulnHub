#  JFrog Artifactory 多个漏洞威胁软件供应链安全   
DO SON  代码卫士   2024-03-08 14:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**JForg Artifactory 中存在多个安全漏洞，可导致软件开发管道遭攻陷。**  
  
  
这些漏洞简述如下：  
  
- CVE-2023-42509：机密泄露 (CVSS 6.6)。该漏洞存在的原因是 Artifactory 管理仓库配置的方式不当。处理不当的错误可被组合用于泄露敏感数据如凭据或内部系统信息。虽然该漏洞本身并不能立即产生灾难性后果，但可使攻击者获得进一步攻陷防御措施的有价值信息。  
  
- CVE-2023-42661：任意文件写（CVSS 7.2）。该漏洞与 Artifactory 的文件处理流程有关。认证攻击者可发送特殊设计的请求，诱骗 Artifactory 编写任意文件，从而可能造成严重后果，如系统崩溃、数据损坏或直接在用户机器上运行恶意代码。  
  
  
  
- CVE-2023-42662：访问令牌泄露（CVSS 9.3）：该漏洞为严重等级的漏洞，可攻陷 Artifactory 的单点登录特性。特殊构造的 web 地址可诱骗用户暴露自己的访问令牌。成功攻击可导致攻击者模拟合法用户并对 Artifactory 环境造成严重损害。  
  
JFrog已修复这些漏洞并提供缓解措施。  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[速修复！TeamCity中存在两个严重的漏洞，可触发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518992&idx=1&sn=7af87c035a996a3b64a0c389013aa003&chksm=ea94ba7adde3336cf762a515bae94e33d55782b3f4e24f46be397a1301e9f26404e7bc16985a&scene=21#wechat_redirect)  
  
  
[谷歌修复代码测试工具Bazel 中的严重供应链漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518821&idx=1&sn=8a1a67b87d1bbad6e1c80390fe7c1c61&chksm=ea94bb0fdde33219950ecb20753f8d0ab99b42fbe0e84141e12196184450ccbc041a602bc10b&scene=21#wechat_redirect)  
  
  
[全球软件供应链安全指南和法规概览](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518721&idx=1&sn=a6c98264bc51488064bb51b337094a5c&chksm=ea94bb6bdde3327db988d0cfef1994c2a1fdb66a6ceb2fc1642bb498e3f0c546fa7478db5dc5&scene=21#wechat_redirect)  
  
  
[TensorFlow CI/CD 漏洞使供应链易遭投毒攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518713&idx=1&sn=488228890f80e6cddbaf68f10821849f&chksm=ea94b893dde331854ccef4bfc911cdf55c73813953a87e512b2677a01372974884a061743505&scene=21#wechat_redirect)  
  
  
[软件供应链投毒 — NPM 恶意组件分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518377&idx=1&sn=9504988637a30aee727161562a17cd5a&chksm=ea94b9c3dde330d5c8364a04723d8e973480d0cd285b4ea0da0b9c6d2640ddcadad09ee6bbb1&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://securityonline.info/jfrog-artifactory-vulnerabilities-patch-now-to-protect-your-software-supply-chain/  
  
  
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
  
