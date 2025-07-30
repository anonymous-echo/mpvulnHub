#  速修复Next.js中严重的授权绕过漏洞   
do son  代码卫士   2025-03-24 18:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**热门的 React 框架 Next.js 能帮助开发人员更快更有效地构建全栈 web 应用，广泛用于大量企业，其中不乏一些全球最大的企业，因其“可通过扩展 React 的最新特性并集成强大的基于 Rust 的 JavaScript 工具以最快进行构建，创建全栈 web 应用”而为人熟知。不过，Next.js 最近发布安全公告披露了一个严重的授权绕过漏洞 (CVE-2025-29927)，值得开发人员关注。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQibcjOr8v3MzwicCCwxlDl5v0N2AC83Ac1jxzCQo6gdsFdfic8bOcEic2v2nr0mD7pqb0XxDH4SodDUw/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2025-29927的CVSS评分为9.1，位于 Next.js 中间件中。Next.js 在安全公告中提到，“如果授权检查发生在中间件中，那么很可能在一个 Next.js 应用中绕过授权检查。”这意味着恶意人员可能能够越权访问依赖于中间件进行认证和授权的应用中受保护的资源和功能。  
  
Next.js 中的中间件在请求到达应用路由之前对其进行拦截和处理中，发挥着重要作用。在中间件中执行授权逻辑时，通常仅允许获得认证和授权的用户访问应用的特定部分。新发现的这个漏洞可使攻击者绕过这些检查，可能导致严重后果如数据泄露、越权操作和服务中断。  
  
Next.js 团队已发布打补丁版本，并明确了必须的安全更新：  
  
- 对于Next.js 15.x，漏洞已在15.2.3中修复  
  
- 对于Next.js 14.x，漏洞已在14.2.25中修复  
  
  
  
如用户使用了其中一个主要版本，则升级至特定的补丁级别是缓解该漏洞的最重要一步。  
  
对于仍然运行 Next.js 老旧版本的用户，尤其是11.1.4至13.5.6，可能无法直接应用最新补丁。在这种情况下，安全公告提供了一个重要的应变措施：“如果无法打补丁到安全版本，则建议阻止包含 x-middleware-subrequest 标头的外部用户请求触及 Next.js 应用。”该标头显然在该漏洞的利用过程中发挥了重要作用而阻止包含该漏洞的请求可能会形成一种临时的防护层。然而，该应变措施可能会对某些应用功能造成影响，完全升级到已修复版本应当仍然是最终的目标。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源认证包Nextauth.js 认证绕过漏洞，可使邮件账户遭接管](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513431&idx=3&sn=fda2413d650ea5dcfb0c44e88ed0e525&scene=21#wechat_redirect)  
  
  
[MongoDB库中存在多个漏洞，可用于在Node.js服务器上实现RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522334&idx=2&sn=474bb8a99d7a850a95b1ba847ff41044&scene=21#wechat_redirect)  
  
  
[Solana 热门 Web3.js npm库有后门，可触发软件供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521692&idx=1&sn=5adc287296024b676e739e74bb3e0ca5&scene=21#wechat_redirect)  
  
  
[热门NPM库 “coa” 和“rc” 接连遭劫持，影响全球的 React 管道](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508946&idx=1&sn=273c58d08a4225306a567cf6a150f40c&scene=21#wechat_redirect)  
  
  
[Rust 严重漏洞可导致 Windows 命令注入攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519261&idx=2&sn=0dedc7825e43786bfe415b3a48661fbe&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://securityonline.info/urgent-patch-your-next-js-for-authorization-bypass-cve-2025-29927/  
  
  
  
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
  
