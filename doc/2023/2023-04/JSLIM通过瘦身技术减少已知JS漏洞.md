#  JSLIM:通过"瘦身"技术减少已知JS漏洞   
原创 NING  安全学术圈   2023-04-10 21:15  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WFxb2EWWK8Fjz8olK6TTB3bjBjiabwoiacicib08WCLJqibNDMT3ba8YJwSwVolWbjoFQu7icX4m7wE6LwQ/640?wx_fmt=jpeg "")  
  
> 原文标题：JSLIM: Reducing the Known Vulnerabilities of JavaScript Application by Debloating原文作者：Renjun Ye, Liang Liu,  Simin Hu, Fangzhou Zhu,  Jingxiu Yang,  Feng Wang原文链接：https://link.springer.com/content/pdf/10.1007/978-3-030-93956-4.pdf?pdf=button发表会议：EISA'21笔记作者：NING@SecQuan笔记小编：ourren@SecQuan  
  
## 1 研究介绍  
  
随着开发的深入，第三方库的引入必不可少。不幸的是，这些库的引入，将会增大代码的攻击面，导致代码的不可预知风险加大。因此通过除去代码中的死代码，漏洞代码等可以帮助代码减少外部代码的风险。本文主要通过漏洞库信息来帮助减少代码的不可预知风险，主要贡献如下：  
- 利用自然处理技术，将漏洞与源代码的关系准确映射到函数层面，仅移除或隔离与漏洞相关且依赖库中未使用的相关代码。  
  
- 考虑了main函数调用的外部依赖库中代码的安全性，使用沙箱将这些代码与应用上下文隔离开来，一定程度上去除了这些安全漏洞。  
  
- 设计实现了 JSLIM，一个用于发现 NodeJS 应用程序中相关漏洞的系统。  
  
## 2 主要架构  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WHIsrl3G2rl7bjlyU1lAng7WfDs6R4ic0cJM4ldiaIdnwH2HUVib2AOfUUVlsOVhwGKZqicgIwUmOjV9w/640?wx_fmt=png "")  
  
图 1 系统架构图  
  
系统架构如上图所示，主要分为三个处理步骤。  
  
**Analysis**  
  
这一步首先通过自然语言处理技术（关键字 + 正则匹配），来获取技术文章、报告、论坛中的 CVE 信息（漏洞类型，CVE 编号，影响 NPM 库），接着计算这些漏洞与代码依赖版本的余弦相似度，进而将漏洞与具体代码中的文件、方法进行对应。  
  
**Debloat**  
  
通过 AST 解析包中的各个代码文件，进而通过 Load Dependency Builder 来建立程序调用图，并通过 require 确定依赖文件，进而找到整个 main 入口的所以函数及文件。最后将带有漏洞的代码进行删除即可。  
  
**Validate**  
  
该模块主要对代码进行验证。例如利用尽可能完善的 Selenium 爬虫来对网站内容进行完整性测试、利用漏洞的攻击脚本来对网站进行安全测试等。  
## 3 实验效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WHIsrl3G2rl7bjlyU1lAng7KrtZFlyvIxQBBalKgnclhE4oaibtxUCR7M9XkpnRf3GL4DZjytcytAQ/640?wx_fmt=png "")  
  
表 1 收集网址  
  
漏洞数据主要来源如表 1 所示。实验选择了 50 多个流行 JavaScript 应用程序进行测试，这里展示了部分程序的实验结果，如表 2 所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6Dibw6L070WHIsrl3G2rl7bjlyU1lAng73MS54q89s3ia9A9icyFphoJINljXTUOOD8PbjV6LCiasgob4Jf4K3Sc6Q/640?wx_fmt=png "")  
  
表 2 实验效果  
  
实验效果可以看出，模型能够处理大部分的漏洞映射，而且能够很好的去除，因此证明该类去膨胀技术在该场景下是有效的。  
## 4 个人思考  
- 这篇文章的创新性更多的体现在 Bloated Code 和 CVE 漏洞的捆绑关系，通过消解膨胀代码，从而降低漏洞风险。而技术难点主要在于映射关系的绑定，而后面的消解工作主要以论文 Minicode 的模式为主，此部分工作缺乏细节工作和创新性。  
  
- 整体来说论文的内容创新性较小，主要工作是将一个软件工程问题转化为安全问题，更多的偏应用方面，不过整体思考的过程和应用方向值得学习和参考。  
  
  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
 有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
  
