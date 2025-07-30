#  风险研究 | AI 安全警钟响起：Manus AI 漏洞暴露的背后真相   
 安全极客   2025-03-21 18:47  
  
## 一场泄露引发的风暴  
  
想象一下，你手中的 AI 智能助手突然暴露了自己的“内心秘密”——核心指令、运行代码，甚至可能泄露你的隐私数据。这不是科幻电影，而是刚刚发生在 Manus AI 身上的真实事件。一名用户通过简单操作，就轻松获取了这款 AI 代理的系统提示词，揭开了 AI 安全隐患的冰山一角。这究竟是怎么回事？背后又隐藏着哪些危险？让我们一探究竟。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/LribBcRfBa9Nic1YiczKeiapWib44cadPFscGFeRjjWOggHPGfiaWhrXo4y8WbLjWOCJqzDcuwVNNz7lZjRkWISNO8VA/640?wx_fmt=gif&from=appmsg "")  
## Manus AI 事件概述  
  
Manus AI 是一款由中国初创公司开发的通用 AI 代理，旨在自主执行复杂任务，如报告编写和数据分析。最近，一名用户通过请求输出特定目录内容（如 /opt/.manus/  
），获取了 Manus AI 的系统提示词和运行时代码。这表明 Manus AI 的输入处理存在漏洞，未能有效隔离敏感指令，属于提示词注入攻击的一种。完整对话链接：https://manus.im/share/lLR5uWIR5Im3k9FCktVu0k  
## 事件起因与危险  
  
这一泄露事件揭示了以下风险：  
- **数据暴露**  
：系统提示词和代码的泄露可能暴露用户数据、专有算法或商业策略。  
  
- **恶意利用**  
：恶意用户可能利用漏洞注入有害命令，操纵 AI 行为或进行未经授权的操作。  
  
- **信任危机**  
：事件可能损害用户对 AI 系统和提供者的信任，影响声誉。  
  
- **法律与监管问题**  
：若涉及个人数据泄露，可能面临法律后果。  
  
- **竞争劣势**  
：专有技术的暴露可能让竞争对手获得不公平优势。  
  
## 关键要点  
- 研究表明，Manus AI 事件涉及系统提示词泄露，可能因输入验证不足导致。  
  
- 证据显示，此事件暴露了 AI 代理的安全风险，包括数据泄露和潜在恶意利用。  
  
- 这一事件可能推动 AI 安全评估需求，但争议在于监管与创新的平衡。  
  
## 更广泛的影响  
  
Manus AI 事件凸显了 AI 开发和部署中安全性的重要性。研究建议，开发者应加强输入验证、访问控制和加密措施，并进行持续监控和审计。AI 社区需制定安全最佳实践，监管机构可能需制定相关指导方针，以平衡创新与安全。  
# 详细报告  
## 引言  
  
近年来，AI 代理技术快速发展，展现出强大的自主执行能力。然而，近期 Manus AI 的事件引发了关于 AI 安全性的广泛讨论。本报告基于公开信息，分析了 Manus AI 提示词泄露事件的起因、潜在危险及其更广泛的影响，旨在为公众提供清晰的理解。  
## Manus AI 事件概述  
  
Manus AI 由中国初创公司开发，定位为通用 AI 代理，能够执行复杂任务，如报告编写、数据分析和内容生成。根据 **Medium 文章：Manus AI 的代理时刻：提示词泄露与风险缓解案例研究)**  
 ，该系统近期因安全漏洞受到关注。一名用户（化名“jian”）发现，通过请求输出内部目录（如 /opt/.manus/  
）的内容，可以获取系统提示词和运行时代码。这一发现表明，Manus AI 的输入处理机制未能有效隔离敏感信息，属于提示词泄露或注入攻击。  
  
根据 **Forbes 文章：AI 代理 Manus 引发伦理、安全与监管辩论**  
，Manus AI 被描述为首个完全自主的 AI 代理，能够思考、规划和行动，引发了社区关于治理和控制的讨论。而 **AIbase 新闻：Manus AI 系统提示词泄露官方回应**  
 进一步指出，jian 通过简单请求目录内容，获取了关键信息和运行时代码，暴露了系统并非独立模型，而是基于 Claude Sonnet 并配备 29 个工具。  
## 事件起因分析  
  
提示词泄露的起因似乎在于 Manus AI 的设计过于开放，允许用户直接访问内部目录。这与提示词注入攻击类似，用户通过精心设计的输入，诱导 AI 模型输出其内部指令。根据 **提示工程 Reddit 讨论：Manus AI 提示词和工具（100% 真实）**  
 ，此类漏洞可能源于 AI 代理的多功能性，其工具访问权限未受严格限制。  
## 潜在危险与影响  
  
这一事件揭示了 AI 代理安全性的多方面风险，具体如下：  
  
<table><thead><tr><th style="color: rgb(53, 53, 53);font-size: 14px;line-height: 1.5em;letter-spacing: 0.04em;text-align: center;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(219, 217, 216);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">风险类别</span></span></section></th><th style="color: rgb(53, 53, 53);font-size: 14px;line-height: 1.5em;letter-spacing: 0.04em;text-align: center;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(219, 217, 216);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf="">描述</span></section></th></tr></thead><tbody><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">数据暴露</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">系统提示词和代码泄露可能暴露用户数据、专有算法或商业策略。</span></span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">恶意利用</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">恶意用户可能利用漏洞注入有害命令，操纵 AI 行为或进行未经授权操作。</span></span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">信任危机</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">事件可能损害用户对 AI 系统和提供者的信任，影响声誉和用户流失。</span></span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">法律与监管问题</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">若涉及个人数据泄露，可能面临法律后果，需遵守数据保护法规。</span></span></section></td></tr><tr style="color: rgb(53, 53, 53);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">竞争劣势</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section style="margin-left: 8px;margin-right: 8px;"><span leaf=""><span textstyle="" style="font-size: 14px;">专有技术的暴露可能让竞争对手获得不公平优势，降低公司市场价值。</span></span></section></td></tr></tbody></table>  
  
根据 **TechRadar 报道：Manus AI 可能成为新 DeepSeek，但初始用户报告问题**  
 ，这一事件也引发了 AI 治理解决方案的讨论，强调需确保 AI 部署的透明度和责任。下图为泄露提示词部分截取。  
  
![爬取的提示词部分](https://mmbiz.qpic.cn/mmbiz_png/LribBcRfBa9Nic1YiczKeiapWib44cadPFscGrkFnQxL0CnO6DbK8RdF1bjOnv5UC3yhFDCENKFYffwdrDPibnGrialuQ/640?wx_fmt=png&from=appmsg "")  
  
爬取的提示词部分  
## 泄露提示词揭示的内核真相  
  
根据泄露内容（可参考 **Gist**  
 链接），Manus AI 的系统提示词详细描述了它的角色定位和能力范围。它被设计为一个“高度自主的 AI 助手”，能够处理从数据分析到内容生成的多种任务。以下是内核的关键特征分析：  
1. **基于Claude Sonnet的底层架构**  
提示词明确提到，Manus 并非完全原创的 AI 模型，而是基于 Anthropic 的 Claude Sonnet 构建。这意味着它的核心语言处理能力依赖于 Claude 的预训练模型，而非自研技术。这样的设计降低了开发成本，但也可能限制了其在特定任务上的优化潜力。  
  
1. **29个工具的模块化扩展**  
Manus 配备了29个内置工具，包括浏览器工具（browser_use  
）、数据分析模块等，用于增强其任务执行能力。这些工具通过提示词中的指令被调用，形成了一个模块化的功能生态。然而，泄露代码显示部分工具（如 browser_use  
）存在混淆迹象，可能是为了掩盖其开源来源或实现细节。  
  
1. **单智能体架构，无多智能体协作**  
与一些前沿 AI 代理不同，Manus 并未采用多智能体系统。它依赖单一核心实例，通过工具调用完成复杂任务。这种设计简化了开发，但也限制了其在需要协同推理或动态分工场景中的表现。  
  
1. **开放性与漏洞并存**  
提示词中未见严格的输入过滤或权限控制指令，这直接导致了用户能通过简单请求访问内部目录。这种开放性可能是为了提升灵活性，但也成为安全漏洞的根源。  
  
## 更广泛的影响  
  
Manus AI 事件凸显了 AI 安全性的紧迫性。研究建议，开发者应从开发阶段开始加强安全措施，包括：  
- 实施严格的输入验证，防止提示词注入。  
  
- 加强访问控制，限制 AI 对敏感数据的访问。  
  
- 使用加密技术保护内部数据。  
  
- 进行持续监控和审计，及时发现潜在威胁。  
  
AI 社区需制定安全最佳实践，例如 **提示词泄露：理解生成 AI 模型中的风险**  
 提到的预防策略，包括模型训练时的安全强化和用户输入的过滤。  
  
此外，监管机构可能需制定指导方针，以平衡创新与安全。根据 **AI 风险管理：超越监管界限**  
 ，AI 系统的全面风险管理框架是建立信任的关键。  
  
对于用户而言，此事件提醒公众在使用 AI 代理时需谨慎，尤其是在涉及敏感信息或关键任务时。根据 **Tom's Guide 文章：我用 5 个提示测试了 Manus 与 ChatGPT，这里是赢家**  
 ，用户应了解 AI 系统的局限性和潜在风险。  
## 结论  
  
Manus AI 提示词泄露事件是 AI 行业的一个警钟，强调了安全性的重要性。通过吸取教训并采取积极措施，我们可以确保 AI 代理既强大又安全，为未来技术发展奠定基础。  
## 引用  
- **Medium 文章：Manus AI 的代理时刻：提示词泄露与风险缓解案例研究**  
 (https://medium.com/@xiweizh/manus-ais-agentic-moment-a-case-study-in-prompt-leak-and-risk-mitigation-b52e0e5753ad)  
  
- **Forbes 文章：AI 代理 Manus 引发伦理、安全与监管辩论**  
 (https://www.forbes.com/sites/torconstantino/2025/03/14/ai-agent-manus-sparks-debate-on-ethics-security-and-oversight/)  
  
- **TechRadar 报道：Manus AI 可能成为新 DeepSeek，但初始用户报告问题**  
 (https://www.techradar.com/pro/manus-ai-may-be-the-new-deepseek-but-initial-users-report-problems)  
  
- **AIbase 新闻：Manus AI 系统提示词泄露官方回应**  
 (https://www.aibase.com/news/16138)  
  
- **提示工程 Reddit 讨论：Manus AI 提示词和工具（100% 真实）**  
 (https://www.reddit.com/r/PromptEngineering/comments/1j7q4ki/manus_ai_prompts_and_tools_100_real/)  
  
- **提示词泄露：理解生成 AI 模型中的风险**  
 (https://learnprompting.org/docs/prompt_hacking/leaking)  
  
- **AI 风险管理：超越监管界限**  
 (https://cloudsecurityalliance.org/artifacts/ai-risk-management-thinking-beyond-regulatory-boundaries)  
  
- **Tom's Guide 文章：我用 5 个提示测试了 Manus 与 ChatGPT，这里是赢家**  
 (https://www.tomsguide.com/ai/i-just-tested-manus-vs-chatgpt-with-5-prompts-heres-the-winner)  
  
- **Gist**  
 (https://gist.github.com/jlia0/db0a9695b3ca7609c9b1a08dcbf872c9)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QmV8xmuDmWRS7dWGRa4sgKPkkH2icicFib9SKIQ1ee0tEJI3vXk9dD4EQ91ano9DPrDv0bXKQopibrfw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1&tp=webp "")  
  
  
  
  
