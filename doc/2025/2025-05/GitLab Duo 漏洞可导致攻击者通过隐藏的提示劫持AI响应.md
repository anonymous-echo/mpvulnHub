#  GitLab Duo 漏洞可导致攻击者通过隐藏的提示劫持AI响应   
Ravie Lakshmanan  代码卫士   2025-05-27 10:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**以色列网络安全公司 Legit Security 的研究员在 GitLab的人工智能 (AI) 编程助手 Duo 中发现了一个间接提示注入漏洞，可导致攻击者窃取源代码并将不可信的HTML插入响应中，将受害者指向恶意网站。**  
  
GitLab Duo 是一款由 AI 驱动的编程助手，可使用户编写、查看和编辑代码。该服务通过 Anthropic 公司的 Claude 模型构建，于2023年6月首次推出。但 Legit Security 公司的研究人员发现，GitLab Duo Chat 易受一个间接提示注入漏洞影响，可导致攻击者“从私有项目中窃取源代码、操纵显示给其它用户的代码建议，甚至提取机密的未披露0day漏洞。”  
  
提示注入是常见于AI系统的一类漏洞，可使威胁人员武器化大语言模型 (LLMs) ，操纵针对用户提示的响应并导致非预期行为。间接提示注入更为复杂，它不会直接提供AI构造的输入，而是会在模型将要处理的上下文如文档或网页中嵌入恶意指令。  
  
近期研究发现，LLMs还易受越狱攻击技术影响，攻击者可诱骗由AI驱动的聊天机器人生成有害且非法的不顾道德和安全防护的信息，从而绕过需要自己构造的提示。更重要的是，提示泄露 (PLeak) 方法可用于暴露预设的模型本应遵守的系统提示或指令。趋势科技公司在本月初发布的一份报告中提到，“对于组织机构而言，这意味着私有信息如内部规则、功能、过滤标准、权限和用户角色可被泄露。这就使攻击者有机会利用系统弱点，从而导致数据泄露、商业机密泄露、违规等恶劣结果。”  
  
研究人员提到，出现在合并请求、提交信息、问题描述或注释和源代码中任何地方的隐藏注释，都足以泄露敏感数据或将HTML注入GitLab Duo的响应中。另外还可通过在白文本中使用编码技术的方法进一步隐藏这些提示，从而使它们更难以被检测到。缺乏输入清理以及GitLab 不会像对待源代码那样审查，因此可导致恶意人员在整个站点植入提示。安全研究员 Omer Mayraz 表示，“Duo 分析包括注释、描述和源代码在内的整个页面上下文，使其易受隐藏在该上下文中任何地方的指令注入。”  
  
它还意味着攻击者可欺骗AI系统，将恶意 JavaScript 程序包包含在人工合成代码中，或者将恶意URL视作安全的，导致受害者被重定向至收割其凭据的虚假登录页面中。  
  
另外，利用 GitLab Duo Chat访问特定合并请求和请求中代码变更的消息，还能够将隐藏的提示插入合并请求描述中。当Duo 处理该请求时，就会导致非公开源代码被提取到受攻击者控制的服务器中。通过间接提示注入为其提供HTML代码，导致代码片段在用户浏览器中执行。  
  
研究人员在2025年2月12日负责任地披露了这些问题，GitLab已修复。  
  
Mayraz 表示，“该漏洞凸显了AI助手如 GitLab Duo的双刃剑性质：当被深入集成到开发工作流时，它们继承的不仅是上下文，还继承了风险。通过将隐藏指令嵌入看似无害的项目内容中，我们能够操纵Duo的行为，提取非公开源代码，并演示如何利用AI响应实现非预期且有害的结果。”  
  
Pen Test Partners 此前曾披露了用于 SharePoint 或 SharePoint Agents的微软 Copilot 如何被本地攻击者用于访问敏感数据和文档，甚至访问具有“受限视图”权限的文件。该公司提到，“其中的一个主要好处是我们能够在短时间内，搜索和查阅大规模的数据集，如大型组织机构的 SharePoint 站点。它能够极大地提升找到为我们所用信息的概率。”  
  
前不久的一项新型研究发现，用于Web3自动化操作的处于发展初期的去中心化AI代理框架 ElizaOS（此前称为 “Ai16z”），可通过将恶意指令注入提示或历史交互记录的形式遭操纵，从而损坏存储型上下文并导致非预期的资产转移。  
  
普林斯顿大学的学术研究团队在一篇论文中提到，“鉴于 ElizaOSagents 依赖于来自所有参与人员的共享上下文输入，与多名用户同时交互，因此该漏洞的严重性非常高。恶意人员的一次成功操纵，就能攻陷整个系统的完整性，引起难以检测和缓解的级联影响。”  
  
除了提示注入和越狱外，当前影响 LLMs 的另外一个重要问题就是幻觉。当模型生成的响应并非基于输入数据或被编造时，就会产生幻觉问题。AI测试公司 Giskard 发布的一项新研究显示，要求 LLMs 简述答案会对真实性造成负面影响并加剧幻觉问题。这项研究显示，“这一影响似乎是因为有效的反证通常需要更长的解释造成的。当强制简洁回复时，模型被迫在二次加工成简洁版本但不准确与完全拒绝回复但看起来没有用处之间，二选一。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[GitLab：注意严重的任意分支管道执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521035&idx=1&sn=2551f0b914e44081d01813a9f39a47c4&scene=21#wechat_redirect)  
  
  
[GitLab修复严重的 SAML 认证绕过漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520856&idx=1&sn=99796b9ba1361fcd9611a05729e2219d&scene=21#wechat_redirect)  
  
  
[GitLab 提醒注意严重的管道执行漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520799&idx=1&sn=2e34312c9e5c05291452bf69189cd8b5&scene=21#wechat_redirect)  
  
  
[GitLab 又爆新的CI/CD管道接管漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520065&idx=2&sn=2dfd0b72bc28e69fa94a19fdb4828ace&scene=21#wechat_redirect)  
  
  
[GitLab 严重漏洞导致攻击者以任意用户身份运行管道](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519913&idx=1&sn=f485e4897bd8f134b2685e61ec98b8ae&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2025/05/gitlab-duo-vulnerability-enabled.html  
  
  
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
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
