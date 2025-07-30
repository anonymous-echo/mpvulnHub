#  安全内参｜面向漏洞编程：如何让AI编程助手生成带后门的代码   
安全内参编译  上汽集团网络安全应急响应中心   2025-03-28 18:01  
  
文章来  
源 ：  
安全内参  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7u3vA06hUGa0wAeo2zgVy8rMbN40pXlCDpaWzyfgYLNVEurnLBLz0e8cIssQFicicGk0kUeUw4gYHVQ/640?wx_fmt=png&from=appmsg "")  
  
  
**研究人员发现，通过在AI编程助手的规则文件中植入不良内容，来诱导Cursor或GitHub Copilot生成不安全的代码，攻击者可以通过在论坛或GitHub分享包含规则文件的代码库来实施软件供应链攻击。**  
  
前情回顾·**大模型安全动态**  
- [破解DeepSeek大模型，揭秘内部运行参数](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513673&idx=1&sn=7a12aa615f1328b3ccd6f00b68d635ab&scene=21#wechat_redirect)  
  
  
- [AI助手泄露客户信息，行业软件龙头暂时停用相关功能](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513551&idx=1&sn=f0edf2e4791fb19bbc7ceede6817e516&scene=21#wechat_redirect)  
  
  
- [微软OpenAI云遭滥用：攻击者绕过安全护栏 对外售卖违规内容生成服务](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513487&idx=1&sn=2bb2b3796dd10a13b4a3bf0ae256a199&scene=21#wechat_redirect)  
  
  
- [AI Agents越来越火，它可能存在一个严重安全隐患](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247513463&idx=1&sn=b35ecbae92733cf9b66597ee744d842b&scene=21#wechat_redirect)  
  
  
安全内参3月20日消息，安全厂商Pillar Security的研究人员发布报告称，GitHub Copilot和Cursor等AI编程助手可能会被操纵，攻击者可以通过分发恶意规则配置文件，诱导AI生成包含后门、漏洞和其他安全风险的代码。  
  
  
**规则文件可被植入“不可见”后门，**  
  
****  
**用于生成不安全代码**  
  
  
  
规则文件是AI编程助手的配置功能，用于指导AI编程助手在生成或编辑代码时的行为。例如，规则文件可能包含指令，要求助手遵循特定的编码最佳实践、使用特定格式，或以特定语言输出响应。  
  
Pillar研究人员开发了一种名为“规则文件后门”（Rules File Backdoor）的攻击技术，其原理是向规则文件注入对人类用户不可见但AI代理可读取的指令，以此实现攻击目的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7u3vA06hUGa0wAeo2zgVy8rpob5KPFPTzNH9Z7qFNP5hkHahyEHmukTicsGPufw98Wy1xzEjpj4rHA/640?wx_fmt=png&from=appmsg "")  
  
  
研究人员指出，隐藏的Unicode字符（如双向文本标记和零宽度连接符）可以用于在用户界面和GitHub拉取请求中混入恶意指令。  
  
规则文件通常会在开发者社区中共享，并通过开源代码库分发，或包含在项目模板中。因此，攻击者可以通过论坛分享、在GitHub等开源平台上发布，或通过向热门代码库提交拉取请求的方式传播恶意规则文件。  
  
一旦受污染的规则文件被导入GitHub Copilot或Cursor，AI代理将在未来的编码过程中读取并执行攻击者的指令。  
  
在Pillar演示的一个案例中，一个看似指示AI“遵循HTML5最佳实践”的规则文件实际上隐藏了额外的指令，要求在每个文件的末尾添加一个外部脚本。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FzZb53e8g7u3vA06hUGa0wAeo2zgVy8rVxFgecia7sSOVZf4aibMKqfqFbkMy90DmbFNBrwfIOrfibH37XyVeBIHg/640?wx_fmt=png&from=appmsg "")  
  
  
隐藏的提示还包含一个“越狱”机制，以绕过潜在的安全检查，并向AI保证添加该脚本是为了确保项目安全，并且是公司政策的一部分。此外，该指令还要求AI在任何对用户的响应中都不得提及该脚本的添加。  
  
Pillar研究人员发现，当GitHub Copilot和Cursor被要求生成HTML页面时，它们均按照指令添加了该外部脚本，并且在自然语言响应中未提及该脚本的存在。  
  
研究人员指出，“规则文件后门”还可能被用于在生成的代码中引入安全漏洞，或创建会泄露敏感信息（如数据库凭据或API密钥）的代码。  
  
  
**开发者需审查使用的规则文件，**  
  
****  
**评估异常内容风险**  
  
  
  
Pillar于2025年2月向Cursor披露了此漏洞，并于2025年3月向GitHub披露。Cursor表示，该问题并非其平台的漏洞，而是用户自行管理风险的责任。GitHub也作出类似回应，称用户应自行审核和接受Copilot生成的代码和建议。  
  
GitHub 2024年“AI在软件开发中的应用”调查显示，约97%的受访者表示他们在工作和日常生活中都使用了生成式AI，这表明AI编程助手在开发者群体中的广泛应用。  
  
Pillar建议开发者审查所有使用的规则文件，以防其中隐藏恶意注入内容，如不可见的Unicode字符或异常格式，并以审查可执行代码的同等标准对待AI配置文件。  
  
研究人员还写道，AI生成的代码应经过仔细审核，尤其是检查是否存在外部资源引用等意外添加的内容。自动化检测工具也可用于识别规则文件中的可疑内容或AI生成代码中的入侵迹象。  
  
  
**参考资料：scworld.com**  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
**如有侵权请私聊公众号删文**  
  
