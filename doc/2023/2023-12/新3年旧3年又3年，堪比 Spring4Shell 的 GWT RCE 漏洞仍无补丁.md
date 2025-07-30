#  新3年旧3年又3年，堪比 Spring4Shell 的 GWT RCE 漏洞仍无补丁   
Becky Bracken  代码卫士   2023-12-19 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSosSf8RU4ibVtYiaEZA3qWAmicnibOgFaxkltzwsYNTnRfQRHKnphr5Il2icy4j1xKen9iaXsGKrpasv5g/640?wx_fmt=png&from=appmsg "")  
  
**距离第一次被发现过了超过8年后，游荡在热门开源应用框架 Google Web Toolkit (GWT) 中的未认证 Java 反序列化漏洞至今仍未被修复，易受攻击的应用可能需要根本性的框架修复方案。**  
  
  
  
GWT 是一款开源工具集，可允许 Web 开发人员通过 Java 语言来创建和维护 JavaScript 前端应用程序。技术追踪平台 Enlyft 提到，目前约2000家企业都在使用 GWT，其中多数规模是1到10名员工，年收入在10美元至100万美元之间。  
  
Bishop Fox 的高管 Ben Lincoln在最近发布的研究中提到，无法想象可导致远程代码执行 (RCE) 后果的 GWT 漏洞竟然还未修复，并提到该 Java 反序列化漏洞类似于在2022年发现的 Spring4Shell 漏洞。Lincoln 写道，“如补丁还未发布，则这个易受攻击的框架特性至少本已被标记为弃用，而该框架文档应提到用更新选择替换易受攻击代码的建议。至少，该框架的开发人员无疑可以更新‘开始’手册和其它文档，提示使用这些易受攻击特性带来的内在危险性，而不是强调突出这一功能。”  
  
Lincoln 提到，与之相反，自2015年GWT问题被首次提及以来，代码维护人员并未采取以上任何一种措施。他在文章中详细说明了易受攻击的 GWT 应用程序如何可遭真实利用。  
  
  
**缓解措施**  
  
  
Lincoln 提醒称，缓解被暴露的 Web 应用的任务将十分艰巨。  
  
该漏洞出现在如此根本性的位置，“保护通过该框架编写的易受攻击的 Web 应用将可能要求对这些应用或框架本身做出架构性的改变。”Lincoln 表示，首先，运行易受攻击应用程序的管理员需要为最糟糕的场景进行规划，并从这点开始着手。他指出，“他们应当思考如果企业必须立即拦截该应用的访问，直到缓解部署之后才能恢复访问，那么我们将如何应对？”更广泛地来说，为了避免这类已知的、未修复漏洞，他建议观察第三方组件运营人员的打补丁响应速度。  
  
他提到，“当它们导向‘不是我们的问题’这类的结果，不是打补丁，而是要评估你所在的公司是否同意这一状态，或者是否可以替换该组件、或者是否创建带有修复方案的自定义版本等。如果被认为该漏洞是低风险级别，则至少每年内部将其追踪为漏洞，观察公司是否还是会得出一样的结论。”  
  
他还表示，“对于自研应用程序，定期查看所依赖的第三方组件清单，考虑迁移热度下降或者开发活动下降的组件，即使这些组件并未被正式摒弃或不受支持。”  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[开源意味着不问责，我们准备好应对比 Log4Shell 更大的安全危机了吗？｜Log4j 一周年特别报道](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515742&idx=1&sn=45dc56d00db3c88017cd5d4dee0e8856&chksm=ea948f34dde3062255b8a0f7bc4fa0927fa8e9588a21d7281d1e928901837ad2d236afe3689c&scene=21#wechat_redirect)  
  
  
[美国政府：伊朗黑客利用Log4Shell 漏洞攻陷联邦机构](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514661&idx=2&sn=059d03a2384d5d57513f1e02a69f1f4d&chksm=ea948b4fdde3025977bec54f5099ef0554974ed2c2a16b192b61bd98eb58875466740d94e666&scene=21#wechat_redirect)  
  
  
[速修复！Apache Commons Text 存在严重漏洞，堪比Log4Shell](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514246&idx=1&sn=05c9cf544ef37daf01a04001b22b2584&chksm=ea9489ecdde300fae250e9a720d8fb6ccb7704229f946b796c6aec685c3e6a9446169ec5ad12&scene=21#wechat_redirect)  
  
  
[黑客组织利用Log4Shell 漏洞攻击美国能源企业](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513979&idx=2&sn=72d6d5f48f01c937bda9d937519e416b&chksm=ea948611dde30f07cbdbf693f897a3068064aeca2729ee662032e6292a8aaa911ce77b17f7e2&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.darkreading.com/cloud-security/unpatched-gwt-vuln-leaves-apps-open-server-side-rce  
  
  
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
  
