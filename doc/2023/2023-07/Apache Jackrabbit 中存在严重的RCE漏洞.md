#  Apache Jackrabbit 中存在严重的RCE漏洞   
DO SON  代码卫士   2023-07-27 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Java 平台的开源内容仓库 Apache Jackrabbit 中存在一个严重的远程代码执行漏洞 (CVE-2023-37895)，可使攻击者利用 RMI 实现中一个 Java 对象反序列化问题在易受攻击系统上远程执行代码。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTC64dm9d8xrebfJjKAGtg3jOfWicmLF9ia1P6ay6mnkWmbBMIdwK0HO9d7lgxjJ0UW60CcaYnic4GIQ/640?wx_fmt=gif "")  
  
  
Apache Jackrabbit 是 Java Technology API (JCR) 的内容仓库实现，是管理仓库内容的综合性平台。它具有强大的能力如结构化和非结构化内容支持、全文本搜索等，广泛用于 web 内容管理系统、文档管理系统和企业内容管理机系统中。  
  
CVE-2023-37895 可通过利用 Jackrabbit 的RMI 接口实现远程代码执行后果。该漏洞存在重大风险，可导致攻击者远程执行任意代码，从而攻陷系统。该漏洞被评级为“严重”，影响 Apache Jackrabbit Webapp 和独立版本1.0.0至2.21.18。  
  
该漏洞源自位于所有Jackrabbit webapp 和独立版本2.20.10和2.21.17中的Java对象反序列化漏洞。利用涉及 “commons-beanutils”组件，其中包含易受通过 RMI 而导致的远程代码执行影响的类。  
  
建议 Jackrabbit 用户立即更新至版本 2.20.11或2.21.18。值得注意的是，老旧的稳定分支 (1.0.x到2.18.x)已被标记为已达生命周期，将不再接收更多更新。然而，即使 Jackrabbit 中不存在可利用的代码，但 RMI 支持的存在就可暴露潜在漏洞。该服务器上的更多组件可能也存在同样问题，因此需要完全禁用RMI访问权限。另外，目前也在讨论在未来的 Jackrabbit 发布中考虑删除 RMI 支持。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[Apache Superset 会话验证漏洞可导致攻击者访问未授权资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516346&idx=2&sn=c84ae42d9a4eab4b30b8eba4a27130a5&chksm=ea94b1d0dde338c6da3cc189e548d10cc3511c1ef2d59f067bd428a6efae2df174b66c93b0f6&scene=21#wechat_redirect)  
  
  
[Apache Linkis 修复多个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516234&idx=1&sn=ba72ac437de85dff898598d11ce97f6d&chksm=ea94b120dde338367ba09290193fddc80c82805257f0aac35587dafcb63dd98f43f418cc767f&scene=21#wechat_redirect)  
  
  
[【已复现】Apache Kafka Connect JNDI注入漏洞(CVE-2023-25194)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515512&idx=2&sn=e98e47bd34da117cc9f366253220df47&chksm=ea948c12dde30504b800504eae806ba06d26ac8b0598b1bc3e9808c2574a3161a52d5a6e6edf&scene=21#wechat_redirect)  
  
  
[Apache Superset中存在严重漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515321&idx=1&sn=4a78d9a57c0023b7b411bfdfd7ad2685&chksm=ea948dd3dde304c5d44d1b6bc680eb189e446a4283f43ff18d0b7adbf8844360d7e20af86e7f&scene=21#wechat_redirect)  
  
  
[Apache ShardingSphere身份认证绕过漏洞(CVE-2022-45347)安全风险通告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515110&idx=1&sn=10da0adc762309a9618737f6e904f5fa&chksm=ea948a8cdde3039a022c5f4a87205395353bc885de41fca990d6d25193688fbce21bc604375a&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://securityonline.info/cve-2023-37895-a-critical-remote-code-execution-in-apache-jackrabbit/  
  
  
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
  
