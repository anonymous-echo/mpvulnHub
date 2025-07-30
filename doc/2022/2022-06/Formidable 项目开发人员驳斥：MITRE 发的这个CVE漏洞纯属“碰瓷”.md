#  Formidable 项目开发人员驳斥：MITRE 发的这个CVE漏洞纯属“碰瓷”   
Charlie Osborne  代码卫士   2022-06-10 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQn24dibDKMGCoahoTE3w4fPDrgOKRic7WSFNENcwASWDq0WKw2UCurl1cqZutOQ56IFN7NIic7Bpvvw/640?wx_fmt=png "")  
  
Formidable 项目的开发人员就 Mitre 公司分配的一个CVE漏洞提出反对。  
  
  
  
Formidable 是一款热门解析器，可从GitHub 下载，用于生产和无服务器环境中。其中Node.js模块和软件库是开源的。  
  
该漏洞即CVE-2022-29622，在五月份公开，CVSS 评分为9.8，属于“严重”级别。目前已出现相关 exploit 演示视频。  
  
  
**上传是设计功能**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQn24dibDKMGCoahoTE3w4fPFZ08ZX76Ovxb3kyA8C6DHk75HBDhGzca3a4PNwXU8A9ibRltYEOWQMA/640?wx_fmt=png "")  
  
  
  
CVE-2022-29622 被描述为位于Formidable 3.1.4 版本中的一个危险的任意文件上传缺陷，可被攻击者用于“通过构造的文件名称执行任意代码”。  
  
然而，这种分类以及CVE编号存在争议，而这一点已在CVE文档中提到。CVE文档指出，“某些第三方对这个问题有争议，因为该产品的常见用例中上传任意文件是预期行为。另外，所有版本中都存在可更改默认文件处理行为的配置选项。”  
  
6月3日，Formidable 项目维护人员兼Guardara 的联合创始人 Zsolt Imre 发布博客文章指出，他“仍然有信心认为Formidable 库和这些问题不存在任何关联。”Imre 指出允许任意文件上传的特性并不一定是漏洞，这取决于用例以及上传文件后是否会存在代码执行行为。  
  
他表示，“攻击者要和 web shell 交互则必须执行代码。因此攻击者必须找到能够说服的流程来接触上传的文件。这并非任意‘接触’！实际上必须被执行才行。如你所见，上下文在这里至关重要。”  
  
  
**无效言论**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQn24dibDKMGCoahoTE3w4fPFZ08ZX76Ovxb3kyA8C6DHk75HBDhGzca3a4PNwXU8A9ibRltYEOWQMA/640?wx_fmt=png "")  
  
  
  
Imre 继续说到，认为该漏洞“可导致攻击者通过构造文件名来执行任意代码”的言论是不正确的，因为“唯一受该漏洞影响的就是确实执行任意代码的情况”，指出该问题不属于软件库的情况。  
  
Imre 指出，Formidable 允许默认上传任意文件的说法更为准确，但这并不意味着该功能本身就是漏洞。如果Formidable易受任意代码执行漏洞影响，则必须能够执行所上传的文件或者允许“自动或按要求”执行内容。  
  
总的来说，Imre 认为当Formidable 是单独的攻击向量时，该漏洞并非有效漏洞。他表示，可以说它是一个bug 或实现不良的特性，但并构成漏洞或对用户带来风险。  
  
Imre 表示，“Formidable 被错误地指控为易受攻击。这一错误指控不合理地打乱了其中一个服务的发布。”他指出正在和 Mitre 组织交涉撤下该CVE编号。Mitre 援引 Formidable 的一名贡献者 “GrosSacASac” 的“易受攻击的条件”予以回应。然而，Imre 指出，Mitre 对评论的理解“有误，GrosSacASac 指的并不是说该库在某些条件下易受攻击，而是说以某种方式使用该库的应用程序易受攻击。”目前，Mitre 并未给出进一步回应。  
  
  
**Imre 的评论**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQn24dibDKMGCoahoTE3w4fPFZ08ZX76Ovxb3kyA8C6DHk75HBDhGzca3a4PNwXU8A9ibRltYEOWQMA/640?wx_fmt=png "")  
  
  
  
Imre 评论称，“如果任何人有时间查看下代码就会了解该默认行为以及该库的配置，就会十分清楚 GrosSacASac 在评论中并不是说的该库的情况。遗憾的是，他/她并未给出回应。我认为在 GrosSacASac 回应之前，Mitre 不会做进一步调查。即使在这种情况下，我们可以看到 Mitre 似乎是根据观点而非事实进行运营，所以我们只能自求多福。”  
  
Imre 还在GitHub 发了一项“挑战”，内容和对Formidable 进行进一步测试以及该CVE编号是否被正确分配有关。  
  
我们将进一步关注事态进展。  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[价值4万美元的微软Azure漏洞 ExtraReplica，没有CVE编号](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511627&idx=1&sn=8437c9d6450d98c727d653f1661b090c&chksm=ea949f21dde316375d993c85f24a29825426042f405f05a45d606e25b9d9520b8a6f34fec4d8&scene=21#wechat_redirect)  
  
  
[MITRE 发布“2021年最重要的硬件弱点”榜单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508877&idx=3&sn=34d4edb5e1c108b17008f4498d0ba816&chksm=ea9492e7dde31bf10eae2582c16938158a296122cada8939364a1400db576857fe4f80798cfa&scene=21#wechat_redirect)  
  
  
[MITRE 发布2021 CWE Top 25 榜单](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247506536&idx=1&sn=ae74a4883cea52102f3f152b43f1600f&chksm=ea94eb02dde3621434684a91cf5f755f9f04a24f73676dbfd906690cbe327ab3980089de4459&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://portswigger.net/daily-swig/formidable-developer-fights-back-against-critical-cve-vulnerability-assignment  
  
  
题图：  
Pixab  
ay License  
  
  
  
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
