#  被别家CEO狂怼，微软火速且老实地修复了严重漏洞后......回怼   
综合编译  代码卫士   2023-08-08 15:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**被 Tenable 公司的 CEO 公开批判“严重不负责任”后，微软修复了位于 Power Platform Custom Connectors 特性中的一个漏洞。该漏洞可导致未认证攻击者访问跨租户应用和 Azure 客户的敏感数据。**  
  
先来看一下这份长长的时间轴：  
  
3月30日：发现问题并通过MSRC告知微软  
  
3月30日：微软确认收到  
  
4月3日：微软证实漏洞存在  
  
6月27日：Tenable 要求更新  
  
7月6日：微软通知 Tenable称问题修复  
  
7月10日：Tenable 通知微软称修复方案不完整  
  
7月11日：Tenable 设立新的 MSRC 案例，追踪未修复问题  
  
7月11日：微软要求延迟公开披露  
  
7月14日：Tenable 表示将从7月17日算起两周后发布安全公告（最初表示在7月24日，后更改到7月31日）  
  
7月20日：微软咨询将要分享的信息  
  
7月21日：Tenable 通知微软称将发布不包括技术详情或PoC的有限安全公告  
  
7月21日：微软确认并通知 Tenable 称将在9月28日发布修复方案  
  
7月25日：Tenable 证实将在9月28日后发布技术详情和 PoC  
  
7月31日：发布有限的安全公告  
  
8月3日：微软微此前受影响的主机执行修复方案  
  
8月3日：微软为所有受影响客户发布修复方案后更新安全公告，内含完整详情  
  
该漏洞的根因在于 Power Platform 内连接器启动的 Azure Function 主机的访问控制措施不当。这些连接器使用集成到当作HTTP 触发器用的由微软管理的 Azure Function 中的C# 代码。  
  
尽管客户与自定义连接器的交互通常经由经验证的 API 实现，但API 端点在未执行认证的情况下将请求推送给 Azure Function。这就导致攻击者有机会利用不安全的 Azure Function 主机并拦截 OAuth 客户端ID和机密信息。  
  
发现并在3月30日报送该漏洞的公司 Tenable 指出，“应当注意的是，它不仅仅是一个信息泄露问题，因为它可访问并与不安全的 Function 主机交互，并出发由自定义连接器代码定义的行为，可造成更多影响。然而，鉴于该服务的性质，对每天连接器造成的影响不一，不通过穷尽测试难以量化这些影响。”  
  
Tenable 公司的 CEO Amit Yoran 提到，“为了让大家了解影响的严重程度，我们团队快速将认证机密披露给一家银行，他们对漏洞的严重性表示深切担忧，我们立即通知微软。”  
  
Tenable 公司还分享了概念验证利用代码和找到连接器主机名和构造 POST 请求与不安全 API 端点交互的步骤。  
  
微软最初开始调查 Tenable 公司提交的报告后发现研究员是唯一利用该问题的人员。7月份进一步分析后，微软认为处于“软删除”状态的一些 Azure Functions 并未得到适当缓解。Tenable 公司指出微软在6月7日部署的修复方案并不完整后，微软最终在8月2日为所有客户修复了这个漏洞。微软在上周五表示，“已为所有客户完全修复了这个问题，客户无需采取任何修复措施。”随后，微软在8月4日开始通过 Microsoft 365 Admin Center 告知所有受影响客户。  
  
尽管如此，但 Tenable 公司认为该修复方案仅适用于新部署的 Power Apps 和 Power Automation 自定义连接器，“微软通过要求 Azure Function 密钥访问 Function 主机及其 HTTP 触发器，为新部署的连接器修复了该问题。我们将建议要求获得所部署修复方案其它详情的客户，向微软求证权威答复。”  
  
  
!  
  
**被公开批评后才发布的修复方案**  
  
  
  
  
微软修复该漏洞花了五个月的时间，但要不是 Tenable 公司的CEO 对微软最初的回应表达强烈不满，估计会花费更多时间。8月2日，Yoran 发布文章谴责微软的做事方式“极端不负责任”以及“公然疏忽”。  
  
更糟糕的是，微软最初承诺在9月份修复该问题，与预期的90天期限相去甚远，而相比之下，大多数供应商在修复漏洞时都会遵循90天期限。这一延期加重了人们对于微软响应自身产品漏洞及时性的担忧。  
  
Yoran 提到，“微软是否修复了可导致多家客户的网络和服务遭攻陷的问题？当然没有。他们实现部分修复方案的时间超过了90天，而且还仅对服务中加载的新应用有效。也就是说，到今天为止，我前面提到的那家银行仍然易受攻击，距离我们报送这个问题已经超过了120天，其它所有在修复方案发布前启动该服务的组织机构也仍然易受攻击。而且，就我们所知，这些组织机构仍然不知道自己正面临风险，因此无法就部署控制和其它风险缓解措施做出明智决策。”  
  
  
!  
  
**微软回怼**  
  
  
  
  
在被怼两天后的8月4日，微软发布帖子反击。  
  
微软解释称调查了 Tenable公司在7月10日的报告后发现“非常小规模的子集”代码和客户面临风险，并在8月2日修复了该漏洞。另外说明了其分两个步骤进行响应的合理性。  
  
微软在帖子中指出，“在准备安全修复方案的过程中，我们经历了大量流程，涉及彻底调查、更新开发和兼容性测试。说到底，开发安全更新是修复方案应用速度和修复方案质量安全之间的微妙平衡。行动过快为客户造成的中断（可用性）要比漏洞带来的风险更高。漏洞非公开期间的目的就是为了能有足够的时间推出高质量修复方案。并非所有修复方案生而平等。某些修复方案是完整的且可以安全快速应用，而另外一些则不然。”  
  
微软在文章中并未提到构建修复方案所需的时间，不过表示，“我们也开始监控活跃利用所报告安全漏洞的情况，如发现则会快速响应。”  
  
Tenable 公司尚未就微软回应置评。  
  
问题来了：你站哪边？  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[从SSRF到RCE：微软不打算修复Office Online Server 中的这个漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514282&idx=1&sn=69e2d2582b23fb9e20f43d03a2aaeac5&chksm=ea9489c0dde300d6341ca1e82b97fbc883e98c8614cc360f22202759fe3ec537ca95ef44ab7a&scene=21#wechat_redirect)  
  
  
[Teams 可被滥用于安装恶意软件，微软或不打算修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494492&idx=4&sn=04eef05f1c7fe8efbd7870f37a4c0d70&chksm=ea94da36dde353206cab5f42438d84c8b3145abd6ad0542176197034fbd131e4e18d16f810b8&scene=21#wechat_redirect)  
  
  
[Drupal 修复严重的站点接管漏洞; 微软向1万名国家黑客受害者发出通知；Libra 不受立法机构信任](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490445&idx=2&sn=cc281dc44277e36b1716b28931502a67&chksm=ea972ae7dde0a3f1abafbdd52411b259818663d1e1e483e4fc4f234b80985c8fb7ef2ecf9564&scene=21#wechat_redirect)  
  
  
[0day！远程桌面服务 0day 可导致会话遭劫持，微软近期不修复](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490117&idx=1&sn=5b2343be14654bd0e68ef99a14179d83&chksm=ea972b2fdde0a2399ed745bb8aca7a2b9002d6b6190e7d5fc4ab7a8d9562dadd53a1e67bd933&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/microsoft/microsoft-fixes-flaw-after-being-called-irresponsible-by-tenable-ceo/  
  
https://www.tenable.com/security/research/tra-2023-25  
  
https://msrc.microsoft.com/blog/2023/08/microsoft-mitigates-power-platform-custom-code-information-disclosure-vulnerability/  
  
https://www.linkedin.com/pulse/microsoftthe-truth-even-worse-than-you-think-amit-yoran/  
  
  
题图：  
Pixab  
ay License  
  
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
  
