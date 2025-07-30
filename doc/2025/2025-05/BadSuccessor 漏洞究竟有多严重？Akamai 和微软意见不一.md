#  BadSuccessor 漏洞究竟有多严重？Akamai 和微软意见不一   
Ryan Naraine  代码卫士   2025-05-23 10:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**Akamai 公司的安全团队公开披露了位于 Windows Server 2025中的一个未修复提权漏洞 “BadSuccessor” 的利用详情。该漏洞可导致攻击者攻陷活动目录中的任意用户。**  
  
Akamai 公司的研究员 Yuval Gordon 提到，微软安全响应中心证实了该漏洞的有效性但将其评级为“中危”级别，并表示将“在未来”修复。Gordon 发表博客文章（包含概念验证），说明了如何将少有人知的服务账号迁移特性转变为严重的安全风险并提到，“虽然我们感谢微软的回应，但我们不认可对它的严重性评估”。  
  
Gordon 提到，该漏洞位于被分配的服务管理账号 (dMSAs) 中，它是在Server 2025 中引入的一个全新类。dMSAs 旨在取代笨重的遗留服务账号，但Gordon 发现它们继承了原始账号所拥有的权限。  
  
他发布技术文档，说明了低权限用户如何能够一步步作为合法继承者创建一个新的 dMSA。Gordon 表示，“这就是域控制器将我当作合法继承者对待的所有要求。谨记：不涉及群成员变更、没有触及与管理员组以及不需要将可疑的 LDAP 写入真实的权限账号。只需两个属性变更，新的对象就会成为继承者，而KDC永远不会质疑这种“血统”；如果存在链接，那么就会获得这些权限。我们没有更改任何一个组成员，没有提权任何现有账号，也没有触发任何传统的提权警报。”  
  
研究员调查客户遥测数据后发现，在91%的环境中，至少有一个非管理员用户已经在组织机构单元层面拥有问题重重的 Create-Child 权限。Gordon 注意到这些权限足以创建一个dMSA，但微软认为攻击者需要“提权访问的特定权限”，因此评级更低。由于Windows Server 2025 域控制器默认启用 dMSA 支持，因此Gordon 认为组织机构只通过将2025 DC 添加到现有的活动目录中，就会继承这一风险。  
  
他表示，促使Akamai 在4月1日通知微软后但最终公开该漏洞的原因是，微软表示不会立即打补丁。Gordon 表示，“他们将它评级为中危漏洞，并表示目前不满足立即打补丁的门槛。”他指出，该漏洞引入了一个此前未知的且影响巨大的绝对路径，使得在OU上拥有 CreatChild的任意用户很有可能攻陷该域名中的任何用户，“并获得类似Replicating Directory Changes 的权限，执行 DCSync 攻击。另外，我们未发现针对 CreateChild 权限，或者更确切地说，适用于 dMSA的CreateChild 的行业实践或工具，这种情况非常令人担忧。我们认为它加剧了漏洞的隐秘性和严重性。”  
  
这种在补丁发布前披露漏洞的行为又引发了长久以来的负责任披露问题。在社交媒体上，一些研究员批评 Akamai 公司在补丁可用之前发布完整攻击详情的行为，而一些传统黑客则认为微软历来存在分类错误以及拒绝修复严重漏洞的问题。  
  
在官方补丁未发布之前，Akamai 公司已发布检测查询、日志指南以及脚本，来定位可创建 dMSA 的责任人。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[通过Spring Boot 绕过Akamai WAF并触发RCE](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515059&idx=2&sn=440e117183a0cd8fc8ad083796317496&scene=21#wechat_redirect)  
  
  
[微软5月补丁星期二值得关注的漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523008&idx=3&sn=9a842c823e7d8913c5cc1c0f69a9cda4&scene=21#wechat_redirect)  
  
  
[8天，这个被微软认为“低可利用性”的漏洞即遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522819&idx=1&sn=005966b8a5fb21a2ac90627b6b0075bc&scene=21#wechat_redirect)  
  
  
[微软利用AI从开源引导加载器中找到20个0day漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522638&idx=1&sn=15b5a925b5a9f1eecca2dc4a721a63a9&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/akamai-microsoft-disagree-on-severity-of-unpatched-badsuccessor-flaw/  
  
  
  
题图：  
Pixabay Licen  
se  
  
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
  
