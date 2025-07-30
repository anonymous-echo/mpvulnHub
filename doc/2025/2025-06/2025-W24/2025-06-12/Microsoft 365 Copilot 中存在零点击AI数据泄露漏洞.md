#  Microsoft 365 Copilot 中存在零点击AI数据泄露漏洞  
Bill Toulas  代码卫士   2025-06-12 09:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
**被命名为 “EchoLeak” 的新型攻击利用的是目前已知的首个零点击AI漏洞，它可导致攻击者从无需交互的用户上下文中，恶意泄露 Microsoft 365 的敏感数据。**  
  
该攻击由 Aim Labs 的安全研究员在2025年1月发现并告知微软，后者为这个信息泄露漏洞分配了编号 CVE-2025-32711，并将其评级为“严重”且在5月份在服务器端修复，因此用户无需任何操作。另外，微软还提到，目前不存在真实利用证据，因此该漏洞未影响任何客户。  
  
Microsoft 365 Copilot 是一款内置到 Office 应用如 Word、Excel、Outlook 和 Teams 中的一款AI助手，通过 OpenAI 的 GPT 模型和 Microsoft Graph 帮助用户生成内容，分析数据并根据用户所在组织机构的内部文件、邮件和聊天等回复问题。  
  
尽管该漏洞已修复且并从未遭恶意利用，不过研究人员将其命名为新的漏洞类型“LLM范围越界”，可导致大语言模型（LLM）在无需用户意图或交互的前提下泄露权限内部数据。  
  
由于该攻击无需与受害者进行交互，因此在企业环境中可被自动化执行静默数据泄露操作，凸显了此类漏洞如部署在AI智能系统中所带来的巨大危险。  
  
  
**EchoLeak 如何运作**  
  
  
  
  
攻击始于向目标发送恶意邮件，其中包含与 Copilot 无关的文本，并被格式化成常见的业务文档形式。  
  
该邮件中内嵌一个隐藏的构造的提示注入，提示LLM提取和渗透内部敏感信息。由于该提示对于人类而言看似是正常消息，因此它绕过了微软的跨提示注入攻击 (XPIA) 分类防护措施。之后，当用户询问 Copilot 一个相关的业务问题时，该邮件就会通过RAG引擎被检索到LLM的提示上下文中。该恶意注入目前已触及LLM，“诱骗”LLM提取敏感的内部数据并将其插入构造的链接或图片中。  
  
研究人员发现某些标记的图片格式可导致浏览器请求该图片，自动将URL包括内嵌数据等发送到攻击者的服务器。微软的内容安全策略拦截的大多是外部域名，但 Microsoft Teams 和 SharePoint URL 是可信的，因此可被滥用于提取数据而不会造成任何问题。  
  
虽然 EchoLeak 漏洞可能已被修复，但将LLM 集成到业务网络越来越复杂，也越来越深入，导致传统的防御措施压力重重。同样，攻击者可静默用于高影响力攻击的新型武器化漏洞越来越多。  
  
企业应当增强其提示注入过滤器、实现颗粒度输入范围划分，以及通过在LLM 输出上应用处理后过滤器的方法，拦截包含外部链接或结构化数据的响应。此外，RAG引擎可配置为排除外部通信，从源头防止检索恶意提示。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[微软扩展Copilot AI漏洞奖励计划范围，提高赏金](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522200&idx=1&sn=7bf07566564fbc663142355517974f16&scene=21#wechat_redirect)  
  
  
[微软GitHub Copilot 被诉违反开源许可条款和侵犯开发人员权益](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514414&idx=1&sn=a937561278e4afeadc5816a57d8be22c&scene=21#wechat_redirect)  
  
  
[用GitHub Copilot 生成的项目中，40%会引入漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507580&idx=1&sn=08367123c0447c0c24fa859f6ecd96c1&scene=21#wechat_redirect)  
  
  
[看我如何通过 OpenAI o3 挖到 Linux 内核远程 0day](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523149&idx=1&sn=0298267a08369cc3ea9bdbdec81eb788&scene=21#wechat_redirect)  
  
  
[GitLab Duo 漏洞可导致攻击者通过隐藏的提示劫持AI响应](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523124&idx=2&sn=11426f6aaac01c747218a552ac6e5129&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/zero-click-ai-data-leak-flaw-uncovered-in-microsoft-365-copilot/  
  
  
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
  
