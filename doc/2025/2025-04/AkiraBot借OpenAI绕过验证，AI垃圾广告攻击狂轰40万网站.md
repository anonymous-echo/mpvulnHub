#  AkiraBot借OpenAI绕过验证，AI垃圾广告攻击狂轰40万网站   
原创 HackerNews  安全威胁纵横   2025-04-11 07:53  
  
AkiraBot 的人工智能（AI）驱动平台被用于向网站聊天框、评论区和联系表单发送垃圾信息，以推广可疑的搜索引擎优化（SEO）服务，如 Akira 和 ServicewrapGO。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok8FsaZqg4zxf4tXPIwEDFgvqxaoGr4yyLaQgWxBZ31ecYYYibxSd3AoruQA7TRyJV35hlxkWTUAp1avT3pe1XA/640?wx_fmt=jpeg "")  
  
  
网络安全研究人员披露了一个名为   
AkiraBot  
 的人工智能（AI）驱动平台的细节，该平台用于向网站聊天框、评论区和联系表单  
发送垃圾信息  
，以推广可疑的搜索引擎优化（SEO）服务，如 Akira 和 ServicewrapGO。  
> “自 2024 年 9 月以来，AkiraBot 已针对超过 40 万个网站，并成功向至少 8 万个网站发送了垃圾信息，”SentinelOne 研究人员 Alex Delamotte 和 Jim Walter 在报告中表示。“该机器人利用 OpenAI 生成基于网站用途的定制化推广信息。”  
  
  
该活动的目标包括中小型企业的联系表单和聊天小部件，其框架使用   
OpenAI 的大型语言模型（LLMs）生成垃圾内容  
。这个基于 Python 的“广泛”工具的独特之处在于，它能够生成内容以  
绕过垃圾信息过滤器  
。  
  
据信，这个批量消息工具自 2024 年 9 月起开始使用，最初名为“  
Shopbot  
”，似乎是指使用 Shopify 的网站。  
  
随着时间的推移，AkiraBot 扩大了其目标范围，包括使用 GoDaddy、Wix 和 Squarespace 开发的网站，以及那些使用 Reamaze 构建的通用联系表单和实时聊天小部件的网站。  
  
该操作的核心——生成垃圾内容——是通过利用 OpenAI API 实现的。该工具还提供了一个图形用户界面（GUI），用于选择要攻击的网站列表，并定制可以同时攻击的网站数量。  
> “通过处理包含机器人应发送消息类型的一般大纲的模板，AkiraBot 为目标网站创建定制的垃圾信息，”研究人员表示。“该模板通过发送到 OpenAI 聊天 API 的提示进行处理，以根据网站内容生成定制化的推广信息。”  
  
  
对源代码的分析显示，OpenAI 客户端使用了 gpt-4o-mini 模型，并被赋予了“生成营销信息的助手”角色。  
  
该服务的另一个显著特点是，它能够绕过 CAPTCHA 障碍，大规模垃圾攻击网站，并通过依赖通常提供给广告商的代理服务来规避基于网络的检测。目标 CAPTCHA 服务包括 hCAPTCHA、reCAPTCHA 和 Cloudflare Turnstile。  
  
为了实现这一点，该机器人的网络流量被设计为模仿合法最终用户，并利用 SmartProxy 提供的不同代理主机来掩盖流量来源。  
  
AkiraBot 还被配置为将其活动记录在一个名为“submissions.csv”的文件中，该文件记录了成功和失败的垃圾信息尝试。对这些文件的检查显示，到目前为止，已有超过 42 万个独特域名被攻击。此外，与 CAPTCHA 绕过和代理轮换相关的成功指标被收集并通过 API 发送到 Telegram 频道。  
  
针对这些发现，OpenAI 已禁用了威胁行为者使用的 API 密钥和其他相关资产。  
> “作者或作者们为此机器人绕过常用 CAPTCHA 技术的能力投入了大量努力，这表明运营商有动机违反服务提供商的保护措施，”研究人员表示。“AkiraBot 使用大型语言模型生成垃圾信息内容，展示了人工智能对防御网站垃圾攻击的新兴挑战。”  
  
  
这一发展与一个名为 Xanthorox AI 的网络犯罪工具的出现相吻合，该工具被宣传为一个一站式聊天机器人，用于处理代码生成、恶意软件开发、漏洞利用和数据分析。该平台还支持通过实时语音通话和异步语音消息进行语音交互。  
> “Xanthorox AI 由五个不同的模型提供支持，每个模型都针对不同的操作任务进行了优化，”SlashNext 表示。“这些模型完全运行在卖家控制的本地服务器上，而不是部署在公共云基础设施上或通过暴露的 API。这种以本地为主的模式大幅降低了被发现、关闭或追踪的可能性。”  
  
  
  
转载请注明出处@安全威胁纵横，封面由ChatGPT生成；  
  
消息来源：https://thehackernews.com/2025/04/akirabot-targets-420000-sites-with.html  
  
  
  
      
更多网络安全视频，请关注视频号“知道创宇404实验室”  
  
  
  
