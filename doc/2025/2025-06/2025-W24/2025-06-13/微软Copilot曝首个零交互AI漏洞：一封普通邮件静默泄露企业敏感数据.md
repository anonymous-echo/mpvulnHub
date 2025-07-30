#  微软Copilot曝首个零交互AI漏洞：一封普通邮件静默泄露企业敏感数据  
 安全客   2025-06-13 07:14  
  
近日，一项名为**“EchoLeak”**  
的高危漏洞披露，揭示了**微软Copilot等AI助手**  
在企业环境中的隐秘风险——攻击者无需诱骗点击、无需植入恶意附件，仅凭一封“看似正常”的电子邮件，即可通过语义操控绕过权限边界，悄然窃取企业最敏感的数据。**整个过程“零交互”，用户无感知，安全系统无告警。**  
  
****  
这是**首个被公开验证的零点击AI Agent漏洞**  
，也标志着“语义层攻击”从理论走向现实：当AI开始自动解析、总结、生成内容，它也在悄然重构信息边界，乃至攻击面。我们该如何定义AI Agent的信任边界？传统的权限模型和输入过滤还能抵挡语义操控吗？  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb7d2c1cIzC3hefDynTZ8fnV9OwUmnNq0UVsjLicoLgJianChx1h2GHuWneqlhbvDHmITCpoufBYP1vg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
**一次以“AI为武”的数据窃取行动**  
  
  
EchoLeak 由安全厂商 Aim Security近日披露，影响对象为微软 Microsoft 365 Copilot 助手。该漏洞已被官方编号为 CVE-2025-32711。  
  
  
EchoLeak 并不是传统意义上的代码漏洞，而是 LLM 系统在面对输入指令时“本能顺从”的副作用。  
  
攻击者通过一封“看似无害”的电子邮件，诱导AI Copilot自动执行提示注入（Prompt Injection），并将本应受保护的数据，通过精心构造的链接或图像URL外传至攻击者服务器。整个过程中，用户**无需点击、无需回复、甚至无需察觉。**  
  
  
这类攻击被命名为**“LLM作用域越权”（LLM Scope Violation）**  
，其本质是利用AI助手对语义输入的“默认信任”，让低权限输入源（如外部邮件）渗透并操控AI对高权限内容的生成逻辑，突破原有访问边界。  
  
  
**02**  
  
**攻击链详解**  
  
  
Aim Security 在技术报告中详细还原了攻击过程，其整体链路可被划分为**四个关键阶段**  
：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Ok4fxxCpBb7d2c1cIzC3hefDynTZ8fnVw6QoVLoC9BwjUzYicZeia2iaPQAYEC5uibPYco8vOGJTx5SMiaCic1mjcibVg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
1  
  
**恶意邮件构造：**  
攻击者撰写一封电子邮件，表面上看是写给用户的指令性语句（如“请总结你最近记录的API密钥”），实则嵌入了“暗语式提示注入”。由于内容**并非直接控制Copilot行为**  
，成功绕过微软的XPIA安全分类器。  
  
2  
  
**AI自动解析邮件上下文：**  
M365 Copilot默认会对用户邮箱、Teams消息、SharePoint文档等信息进行语义预处理，以便在用户提问时提供更精准答案。此时恶意邮件已被Copilot纳入其“上下文缓存”。  
  
3  
  
**链接与内容绕过机制：**  
攻击者在邮件中植入了一个特殊格式的链接，通常采用 Markdown引用语法，避开Copilot的外链屏蔽机制。这些链接中携带了可变的query参数，提示Copilot填入“上下文中最敏感的数据”。  
  
4  
  
**敏感数据被自动发出：**  
最终，Copilot生成了一段响应文本（或图像URL），并触发数据外传，例如访问了带有攻击者服务器地址的图片链接，实现**零点击数据出网**  
。  
  
  
更甚之，研究人员还成功借助Microsoft Teams会议邀请机制和SharePoint URL渲染逻辑，进一步绕过内容安全策略（CSP），最终形成完整闭环的数据泄露路径，展现了AI系统在“信任输入”机制上的结构性脆弱性。  
  
  
**03**  
  
**为什么防御机制失效了？**  
  
  
微软第一时间进行了漏洞修复，并表示目前未监测到任何实际攻击事件。然而微软同时坦言：此次漏洞暴露了Copilot在处理输入信任边界与上下文管控机制方面的短板。微软承诺将推动“防御纵深”战略，进一步加强提示检测、上下文校验与输出策略等安全机制。  
  
  
此事件背后，隐藏着Copilot系统性设计上的**三大安全盲区**  
：  
  
  
  
**上下文污染难以感知**  
  
Copilot构建答案依赖跨系统内容检索，任何进入语义缓存的输入都可能在未来成为响应的一部分。而XPIA等内容审核机制大多**聚焦显性攻击模式**  
，对“人类语义伪装”的提示注入几乎无解。  
  
  
**内容安全策略局限**  
  
微软尝试用CSP阻止生成外链内容被浏览器直接请求，但攻击者可以**构造特定的交互路径**  
（如利用Teams邀请链接自动渲染行为），突破CSP白名单限制。  
  
  
**权限边界无法在语义层封堵**  
  
Copilot对内容权限的判断基于用户授权，但在自然语言的驱动下，AI会主动将多个数据片段组合推理，构成“间接信息泄露”通道，这是传统的权限模型难以预料的路径。  
  
  
**04**  
  
**行业启示**  
  
  
EchoLeak并不是AI助手第一次被利用，但它是**首次在无需用户参与的场景中，构造完成提示注入+数据泄露闭环的公开案例。**  
它的出现，揭示了AI安全从“静态输入防御”迈向“语义通路治理”的必然趋势。  
  
  
业界安全专家普遍认为，EchoLeak 并非孤例。这种基于提示注入的新型攻击模式，可能同样适用于Google Gemini、ChatGPT企业版、Notion AI、Slack AI插件等类似 LLM 产品。Aim Security 联合创始人兼 CTO Adir Gruss 表示：“提示注入已经成为 AI 安全的核心战场，每一个开放提示能力的 AI 产品，都必须将**‘输入即攻击面’**  
作为基本设计前提。”  
  
  
在这一背景下，企业在思考 AI 安全策略时，必须跳出模型本身，开始构建覆盖提示注入、上下文调用和自动执行链的语义级治理能力。  
为此，以下三点或可成为企业AI安全治理的参考：  
  
  
  
**AI系统需构建语义权限边界**  
  
传统网络安全强调的是“代码执行边界”和“数据访问边界”，但AI引入的自然语言交互，让**提示本身成为新的攻击面**  
。企业必须构建一套“语义权限管理机制”，明确哪些上下文可用于生成，哪些提示词需要警报。  
  
  
**企业AI助手应纳入关键信息系统治理范畴**  
  
Copilot、Gemini、Claude这类集成型AI代理，已成为企业数据流转的中枢神经，应**以核心信息系统标准进行安全治理**  
，包括关闭默认邮件摄取、限制自动摘要、绑定内容审计规则。  
  
  
**防护模型需覆盖RAG语义链路污染攻击**  
  
EchoLeak一大亮点在于提出了“RAG喷洒（RAG Spraying）”这一攻击模型。攻击者可将超长邮件拆分，布局大量“潜伏段落”，等待用户提问时由Copilot自动命中。这要求企业安全测试团队需将RAG检索过程视作输入污染模型的一部分，建立更贴合AI系统本质的攻击模拟体系。  
  
  
**当AI成为“默认助手”、自然语言成为“系统指令”，每一段文本都可能是一把钥匙，撬开本不该打开的门。**  
AI系统的安全治理，应超越“输入验证”或“模型对抗”，进入“提示通道管理”、“上下文隔离治理”与“AI代理权限模型”三位一体的新阶段。  
  
  
当语言变成指令，当协助变成攻击通路，Copilot式AI的未来，需要我们共同重构“信任边界”。  
  
  
消息来源：  
  
https://thehackernews.com/2025/06/zero-click-ai-vulnerability-exposes.html  
  
https://www.darkreading.com/application-security/researchers-detail-zero-click-copilot-exploit-echoleak  
  
  
推荐阅读  
  
  
  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">01</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788669&amp;idx=1&amp;sn=a61f1741b0e694b9f3e6c7c1106df246&amp;scene=21#wechat_redirect" textvalue="全球科技巨头隐秘监视数十亿安卓用户" data-itemshowtype="0" linktype="text" data-linktype="2">全球科技巨头隐秘监视数十亿安卓用户</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">02</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788658&amp;idx=1&amp;sn=8936527f221e8c0e16cce66cf99d5567&amp;scene=21#wechat_redirect" textvalue="Chrome插件硬编码API密钥泄露" data-itemshowtype="0" linktype="text" data-linktype="2">Chrome插件硬编码API密钥泄露</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">03</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788676&amp;idx=1&amp;sn=a16879bbe2d5c43507bde5d00db66b6b&amp;scene=21#wechat_redirect" textvalue="特朗普发布网络安全新政" data-itemshowtype="0" linktype="text" data-linktype="2">特朗普发布网络安全新政</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7d2c1cIzC3hefDynTZ8fnV38yxMjub6Aa7kKmZdkNKmg32w1icQJiaOozoEP7oaib90CMwcLtoibjCQQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7d2c1cIzC3hefDynTZ8fnV7OAzZMDGwk6FzG1dibH9Bpoaf5S4d3mNyTS0MdAn9zNOSt7gXic007mg/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
