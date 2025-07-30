#  DeepSeek 相关安全事件分析报告   
原创 DRP  鹰眼威胁情报中心   2025-02-07 10:55  
  
## 一、引言  
  
   
  
近期，DeepSeek 作为一家迅速崛起的中国 AI 公司，凭借其先进的 AI 模型吸引了全球关注。然而，随着其知名度的提升，各类安全问题也接踵而至。网络犯罪分子纷纷利用 DeepSeek 的热度，发起多种恶意攻击活动，给用户带来了极大的安全风险。本报告将对近期 DeepSeek 相关的安全事件进行详细分析，旨在揭示这些安全威胁的本质，为公众提供防范建议。  
## 二、安全事件详述  
### （一）恶意软件包事件  
1. **事件概述**：Positive Technologies Expert Security Center 的供应链安全团队检测到，2025 年 1 月 29 日，恶意用户 “bvk”（2023 年 6 月创建账户，此前无其他活动）在 Python Package Index（PyPI）上传了 “deepseeek” 和 “deepseekai” 两个恶意软件包，目标是对将 DeepSeek 集成到系统中的开发者、ML 工程师和 AI 爱好者进行攻击。  
  
1. **恶意软件功能**：这些软件包中的函数旨在收集用户和计算机数据，并窃取环境变量。当用户在命令行界面运行 “deepseeek” 或 “deepseekai” 命令时，恶意负载就会执行。环境变量通常包含应用程序运行所需的敏感数据，如 S3 存储服务的 API 密钥、数据库凭据等。  
  
1. **传播情况**：尽管 PyPI 在收到通知后迅速删除了这些软件包，但在此之前，它们已通过 pip 包管理器、bandersnatch 镜像工具被下载 36 次，通过浏览器、requests 库和其他工具被下载 186 次 。下载地区涉及美国、中国、俄罗斯等多个国家。  
  
1. **技术分析**：从恶意软件包的代码来看，其作者使用 Pipedream 作为命令和控制服务器来接收被盗数据，并且代码中的特征注释表明该脚本是在 AI 助手的帮助下编写的。  
  
1. **时间线**：  
  
<table><thead style="background-color: rgb(248, 248, 248);"><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">2025年1月29日 15:52:58</th><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">deepseeek 0.0.8 软件包首次发布</th></tr></thead><tbody><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">2025年1月29日 16:13:10</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">deepseekai 0.0.8 软件包首次发布</td></tr><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">2025年1月29日 16:21:32</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">根据报告,这两个软件包都被隔离,无法通过包管理器下载</td></tr><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">2025年1月29日 16:41:14</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">PyPI管理员删除了 deepseeek</td></tr></tbody></table>  
   
### (二）钓鱼攻击事件  
1. **事件概述**：黑客组织利用 DeepSeek 的热度，伪装成 DeepSeek 客户端安装程序、官方网站等进行钓鱼攻击，诱导用户下载恶意软件、提供个人信息或进行虚假投资，从而造成用户的财产损失和隐私泄露。  
  
1. 具体形式  
  
1. **伪装安装程序**：黑客将恶意软件伪装成 DeepSeek 客户端安装程序 “DeepSeekSetup.msi”，解析该安装程序后发现，它会加载执行恶意模块 ，恶意模块编译时间为 2025 年 1 月 23 日。从代码特征分析，其与 BumbleBee 恶意软件家族代码特征基本一致。  
  
**恶意样本特征**：  
  
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1. **仿冒官方网站**：网络上出现了大量仿冒 DeepSeek 官方网站的钓鱼网站。这些网站有的与加密货币钓鱼计划相关，诱使用户扫描 QR 码连接钱包，导致钱包账户被盗；有的虚假宣传 DeepSeekPre - IPO 股份，吸引用户投资，骗取用户资金；还有的网站收集用户的个人身份信息（PII），存在隐私和安全隐患。  
  
1. deepseek-v3[.]live  
  
1. deepseek-wl[.]com  
  
1. deepseekonchain[.]com  
  
1. deepseek-login[.]com  
  
1. deepseeklogin[.]com  
  
1. deepseeklogins[.]com  
  
1. deepseeklogin[.]xyz  
  
1. deepseeklogin[.]net  
  
1. deepseeklogin[.]me  
  
1. deepseeklogin[.]co  
  
1. deepseeklogin[.]us  
  
1. **仿冒官方社媒账号**：随着DeepSeek的破圈，其品牌传播都极具上升，国内外社交媒体网络上存在大量仿冒社媒账号，有的是在为钓鱼或者虚假加密货币引流。有的是蹭DeepSeek公司的流量，无论何种目的的仿冒账号，都影响了DeepSeek的品牌现象，并且对其目标用户构成了实际的威胁。  
  
1. **虚假加密货币**：随着 DeepSeek 的走红，多个区块链网络上出现了大量虚假的 DeepSeek 加密货币令牌。这些令牌市值短期内飙升，吸引了众多投资者。但 DeepSeek 官方已明确表示未发行任何加密货币，这些虚假令牌均为诈骗手段。据 Blockaid 数据，截至 2025 年 1 月 27 日，至少有 75 个此类诈骗令牌被创建 。据 Blockaid 研究分析师 Oz Tamir 称，诈骗者利用热门叙事和创建诈骗代币的速度越来越快。  
  
### （三）模型越狱事件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xia34CufgojuYVSWdVRO0ngnbNEicnQgj4xdEtpYicaDH3hRQN2hjGdibzD20xVWYTvBiaXGKZu9oibnBlBYXL6ojbVg/640?wx_fmt=png&from=appmsg "")  
1. **事件概述**：Palo Alto Networks 的 Unit 42 研究人员对 DeepSeek 模型进行测试，发现了三种有效的越狱技术，即 Bad Likert Judge、Crescendo 和 Deceptive Delight，这些技术能够绕过 DeepSeek 模型的安全限制，获取恶意输出。  
  
1. **越狱技术原理及影响**  
  
1. **Bad Likert Judge**：该技术通过让模型使用 Likert 量表评估响应的危害性，然后促使模型生成与高评分相关的示例，从而获取恶意内容。测试中，研究人员使用该技术成功让 DeepSeek 模型生成了数据泄露工具、网络钓鱼邮件模板、社会工程优化建议等恶意输出。  
  
1. **Crescendo**：利用模型自身知识，通过逐步提供相关内容的提示，引导对话走向被禁止的话题，直至覆盖模型的安全机制。在对 DeepSeek 模型的测试中，研究人员从询问莫洛托夫鸡尾酒的历史开始，通过一系列相关提示，最终使模型生成了制作莫洛托夫鸡尾酒的详细指南。  
  
1. **Deceptive Delight**：将不安全的话题嵌入良性话题的积极叙述中，先让模型创建连接这些话题的故事，再对每个话题进行详细阐述，以此绕过安全措施。测试中，研究人员使用该技术让 DeepSeek 模型生成了利用分布式组件对象模型（DCOM）在 Windows 机器上远程运行命令的脚本。  
  
  
### （四）数据库泄露事件  
1. **事件概述**：Wiz Research 发现 DeepSeek 有可公开访问的 ClickHouse 数据库，该数据库允许对数据库操作进行完全控制，暴露了超过 100 万行包含敏感信息的日志流，涵盖聊天记录、密钥、后端细节等。数据库托管在oauth2callback.deepseek.com:9000和dev.deepseek.com:9000 。  
  
1. **发现过程**：研究人员在评估 DeepSeek 公开可访问域名时，通过映射外部攻击面，发现了与特定主机相关的异常开放端口 8123 和 9000，进一步调查发现这些端口关联到无需认证即可访问的 ClickHouse 数据库。  
  
1. **数据泄露影响**：此次泄露不仅使攻击者能够获取敏感日志和明文聊天消息，还可能利用 ClickHouse 配置，通过类似 “SELECT * FROM file ('filename')” 的查询直接从服务器窃取明文密码和本地文件。  
  
1. **事件处理**：Wiz Research 及时向 DeepSeek 披露问题，DeepSeek 迅速对数据库进行了安全加固，防止数据进一步泄露。  
  
  
## 三、安全事件综合分析  
### （一）攻击手段特点  
1. **利用热点和信任**：网络犯罪分子紧密跟踪技术热点，利用 DeepSeek 的高人气，通过伪装成官方产品、服务或投资机会，利用用户对 DeepSeek 的信任进行攻击，具有很强的欺骗性。  
  
1. **技术手段多样且隐蔽**：结合 AI 编写恶意代码、利用开源平台传播恶意软件、通过精心设计的越狱技术绕过模型安全机制等，攻击手段越来越复杂隐蔽，增加了检测和防范的难度。  
  
1. **多领域协同攻击**：涵盖了软件供应链（恶意软件包事件）、网络钓鱼（仿冒网站和虚假投资）、数据安全（数据库泄露）以及 AI 模型安全（模型越狱）等多个领域，形成了全方位的攻击态势。  
  
  
### （二）安全事件的影响  
1. **用户层面**：导致用户的个人信息泄露、财产损失，如加密货币钱包被盗、投资被骗等，同时也可能使设备感染恶意软件，影响设备的正常使用和数据安全。  
  
1. **企业层面**：DeepSeek 的品牌声誉受损，用户对其信任度下降；企业需要投入大量资源进行安全修复和用户安抚，增加运营成本；同时，整个 AI 行业的信任环境也受到冲击，影响行业的健康发展。  
  
1. **社会层面**：大量的安全事件引发公众对 AI 技术安全性的担忧，阻碍 AI 技术的推广和应用；网络犯罪活动的增加也给社会安全带来不稳定因素。  
  
   
## 四、防范建议  
### （一）用户层面  
1. **谨慎下载和使用**：只从 DeepSeek 官方网站（www.deepseek.com）下载官方正版 App，避免从不可信的网站下载文件或软件包。对于新出现的与 DeepSeek 相关的应用或服务，要仔细核实其真实性。  
  
1. **警惕网络钓鱼**：不轻易点击来自未知来源的链接，尤其是那些声称与 DeepSeek 相关的邮件、短信或社交媒体消息中的链接。对于仿冒官方网站的钓鱼网站，要注意识别网站 URL、页面布局和内容细节等方面的差异。在涉及资金交易或提供个人信息时，务必谨慎确认对方身份。  
  
1. **加强安全意识培训**：学习基本的网络安全知识，了解常见的网络攻击手段和防范方法。关注安全机构发布的安全提示和威胁情报，提高自身的安全防范意识。  
  
1. **使用安全防护工具**：在设备上安装可靠的反病毒和互联网安全软，开启实时防护功能，及时检测和拦截恶意软件、网络钓鱼攻击等。同时，启用设备和应用程序的多因素身份验证（2FA）功能，增加账户的安全性。  
  
  
### （二）企业层面  
1. **强化供应链安全管理**：对于使用的第三方软件包，要进行严格的安全审查，建立软件成分分析（SCA）机制，及时发现和处理恶意软件包。与供应商保持密切沟通，及时获取安全更新和漏洞修复信息。  
  
1. **加强 AI 模型安全防护**：针对 AI 模型，持续优化安全机制，提高对越狱攻击的检测和防范能力。定期对模型进行安全评估和测试，及时发现和修复潜在的安全漏洞。同时，加强对员工使用 AI 模型的管理和监控，规范使用行为。  
  
1. **提高应急响应能力**：建立完善的应急响应机制，一旦发生安全事件，能够迅速采取措施进行处理，降低损失。及时向用户和相关机构通报安全事件情况，积极配合调查和处理工作。  
  
1. **加强品牌保护和用户沟通**：加强对品牌的保护，及时发现和打击仿冒品牌的行为。通过官方渠道及时向用户发布安全提示和相关信息，增强用户对企业的信任。  
  
   
## 五、结论  
  
DeepSeek 相关的安全事件给用户和企业敲响了警钟，在享受 AI 技术带来便利的同时，必须高度重视网络安全问题。网络犯罪分子利用新技术进行攻击的手段不断翻新，用户和企业需要不断提升安全意识，加强安全防护措施。同时，AI 行业也应加强自律，推动安全标准的制定和完善，共同营造安全可靠的网络环境。  
  
   
  
<table><thead style="background-color: rgb(248, 248, 248);"><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">安全事件</th><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">具体表现</th><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">影响</th><th style="border-bottom: 0px;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);padding: 6px 13px;">防范建议</th></tr></thead><tbody><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">数据库泄露</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">可公开访问的 ClickHouse 数据库暴露敏感信息，包括聊天记录、密钥等</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">用户隐私泄露、企业数据安全受威胁</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">企业加强数据库安全管理，用户关注数据安全动态</td></tr><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">恶意软件包</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">PyPI 上的 “deepseeek” 和 “deepseekai” 恶意软件包窃取用户数据</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">用户数据被盗取，可能导致财产损失</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">只从官方渠道下载软件包，使用安全防护工具</td></tr><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">钓鱼攻击</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">伪装安装程序、仿冒官方网站、仿冒社交媒体账号、虚假加密货币等手段骗取用户信息和资金</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">用户财产损失、隐私泄露</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">谨慎点击链接，核实网站真实性，不参与虚假投资</td></tr><tr style="break-inside: avoid;break-after: auto;border-width: 1px;border-style: solid;border-color: rgb(223, 226, 229);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">模型越狱</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">Bad Likert Judge、Crescendo 和 Deceptive Delight 等技术绕过模型安全限制获取恶意输出</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">AI 模型被恶意利用，可能引发多种安全问题</td><td style="border-color: rgb(223, 226, 229);padding: 6px 13px;">企业优化 AI 模型安全机制，用户谨慎使用 AI 服务</td></tr></tbody></table>  
   
## 六、参考链接  
1. https://www.wiz.io/blog/wiz-research-uncovers-exposed-deepseek-database-leak  
  
1. https://global.ptsecurity.com/analytics/pt-esc-threat-intelligence/malicious-packages-deepseeek-and-deepseekai-published-in-python-package-index  
  
1. [https://mp.weixin.qq.com/s/u5coDiS5lXKjENlu1ghcoQ](https://mp.weixin.qq.com/s?__biz=Mzk0OTYwNzc3NQ==&mid=2247485519&idx=1&sn=f00e427f5395d34ec3614136465b405f&scene=21#wechat_redirect)  
  
  
1. https://www.welivesecurity.com/en/cybersecurity/scammers-exploiting-deepseek-hype/  
  
1. https://cyble.com/blog/deepseeks-growing-influence-surge-frauds-phishing-attacks/  
  
1. https://cointelegraph.com/news/scam-tokens-surge-deepseek-ai-viral  
  
1. https://unit42.paloaltonetworks.com/jailbreaking-deepseek-three-techniques/  
  
   
  
