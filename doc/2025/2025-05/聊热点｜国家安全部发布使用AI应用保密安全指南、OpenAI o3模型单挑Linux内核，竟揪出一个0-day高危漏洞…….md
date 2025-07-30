#  聊热点｜国家安全部发布使用AI应用保密安全指南、OpenAI o3模型单挑Linux内核，竟揪出一个0-day高危漏洞……   
 中国电信安全   2025-05-30 08:13  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Dh3fqSPAOWco1mfGDsichHErDfemryHfWvicHaa6kKT6muuDJJhI46ckTic04hgyqvKglMEtwLCqZZwqibiaIItUibTw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**01**  
  
**行业动态**  
  
**国家安全部发布使用AI应用保密安全指南**  
  
  
  
随着人工智能技术的迅猛发展，AI应用在文字处理、数据分析、个性化服务等领域展现了卓越的能力，前所未有地融入我们工作和生活的方方面面。需要注意的是，我们在享受技术红利之时，也应警惕数据安全与隐私保护等问题，特别是其存在的泄密风险隐患，妥善保护好个人信息和敏感数据。  
  
参考来源：国家安全部  
  
**https://mp.weixin.qq.com/s/mLxRu5yasAURYX74K0fsAQ**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Dh3fqSPAOWf7o0q27xAQGukO7sMGpfm06jsLiaThh2ZiayEjdGqjRiaVAZqDJXQEX2eZBeqOFUxWLTzUic4Lars8yQ/640?wx_fmt=png "微信图片_20230601160940.png")  
  
**热评时刻：**  
  
国家安全部发布的使用AI应用保密安全指南强调了在享受AI技术带来便利的同时，需警惕数据安全与隐私保护问题。指南建议优先选择正规平台，避免通过非官方途径下载应用，审慎授予权限，并定期清理个人信息痕迹以减少泄露风险。尤其重要的是，“涉密不上网，上网不涉密”的原则，提醒我们在处理敏感信息时应采取物理隔离等措施。此指南及时且必要，为公众在数字时代如何安全地使用AI提供了明确方向，强化了个人和组织的安全意识与防护能力。  
  
**—— 电信安全专家 李亚**  
  
  
**02**  
  
**国内外安全事件**  
  
**OpenAI o3模型单挑Linux内核，竟揪出一个0-day高危漏洞**  
  
  
#   
  
  
  
  
零日漏洞或零时差漏洞是指软件或硬件中还没有有效补丁的安全漏洞，并且其供应商通常不知晓，而零日攻击或零时差攻击则是指利用这种漏洞进行的攻击。最近，安全研究员 Sean Heelan 分享了他利用OpenAI的o3大模型，在完全不依赖其他工具、框架或辅助代码的前提下，成功发现了 Linux 内核中的一个零日漏洞。这个漏洞现已被正式编号为 CVE-2025-37899，属于一种发生在 SMB 协议“logoff”命令处理路径中的 use-after-free（释放后使用）问题。  
  
参考来源：  
FreeBuf  
  
**https://www.freebuf.com/news/432318.html**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Dh3fqSPAOWf7o0q27xAQGukO7sMGpfm06jsLiaThh2ZiayEjdGqjRiaVAZqDJXQEX2eZBeqOFUxWLTzUic4Lars8yQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "微信图片_20230601160940.png")  
  
**热评时刻：**  
  
文章报道了OpenAI的o3模型在Linux内核的SMB实现中成功发现了一个远程0-day漏洞（CVE-2025-37899），并通过一系列基准测试和真实代码测试，展示了其相较于其他工具（如Claude Sonnet 3.7）更优越的漏洞检测能力。o3模型不仅重新确认了已知的UAF漏洞，还发现了新的类似漏洞，并生成了结构清晰、易于理解的报告。这一成果表明了AI技术在自动化漏洞检测中的巨大潜力，但目前也还是存在误报率较高和需要人工甄别有效信息的情况。总体而言，o3模型的应用为网络安全领域带来了显著的进步和启示，通过持续学习与优化，AI将会有效地推动整个行业技术的发展。  
  
**—— 电信安全专家 李昀驰**  
  
  
**03**  
  
**前沿技术**  
  
**Gartner：中国IT解耦应避免的三大陷阱**  
  
  
#   
  
  
  
  
随着地缘政治紧张局势不断升级以及合规和本地监管规则愈加严格，在中国经营的跨国企业当前面对的业务环境更加复杂。这些挑战促使许多企业对其IT系统进行解耦，以更好地适应中国市场要求和支持其中国境内业务。但是，解耦并非总是解决这些难题的最适合方法；而且，这一决策往往会因为忽略业务成本而有失偏颇，带来成本高昂、复杂性增加和用户体验下降等问题。Gartner发现，企业在中国实施IT解耦时常常会遇到一些陷阱。  
  
参考来  
源：Gartner  
  
**https://mp.weixin.qq.com/s/OUvJxbFDGYchj6aILBR1og**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Dh3fqSPAOWf7o0q27xAQGukO7sMGpfm06jsLiaThh2ZiayEjdGqjRiaVAZqDJXQEX2eZBeqOFUxWLTzUic4Lars8yQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "微信图片_20230601160940.png")  
  
**热评时刻：**  
  
文章指出企业在IT解耦时易陷入三大陷阱：防火墙隔离增加管理复杂性、未评估风险就解耦致资源浪费、盲目用本土安全工具增技术复杂性。其中，使用防火墙进行网络隔离虽然能降低合规风险，但增加了管理复杂性和网络中断风险，这表明传统的网络边界防护手段在面对复杂的业务环境和用户行为时存在局限性。身份优先战略的提出，强调了身份认证和访问控制在网络安全中的重要性，这与零信任安全模型的理念相契合，即通过持续验证用户和设备的身份来确保安全，而不是单纯依赖网络边界。****  
  
  
**—— 电信安全专家 廖建亚**  
  
版权声明：转载及点评的所有文章、图片、音视频文件等资料的版权归版权所有权人所有。此篇采用的文章及图片等内容无法一一联系确认版权者。如涉及作品内容、版权和其它问题，请及时通过电子邮件通知我们以便迅速采取适当措施避免风险。  
联系邮箱：market@damddos.com  
  
**排版：**  
武云龙  
  
**校对：**  
李雪、陈师慧****  
  
**执行主编：**  
田金英  
  
**主编：**  
冯晓冬  
  
**内容整理：**  
市场经营部  
  
**推荐阅读**  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNDY0MjMxNQ==&mid=2247534083&idx=3&sn=547aeb5e88542d8ce0ec2a9ed25fb7f0&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzkxNDY0MjMxNQ==&mid=2247534182&idx=2&sn=997c6de7a6e0bd226ef0acfce44006ea&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzkxNDY0MjMxNQ==&mid=2247534182&idx=2&sn=997c6de7a6e0bd226ef0acfce44006ea&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzkxNDY0MjMxNQ==&mid=2247535888&idx=2&sn=5363fd2a23c0f5cca2dbb0fec3d5a955&scene=21#wechat_redirect)  
  
**聊热点｜AI Agent安全该怎么做？微软安全打了个样、对抗性机器学习：AI模型安全防护新挑战……**  
  
  
****  
**聊热点｜《网络安全等级保护条例》迎来重要进展、迪奥证实“中国客户信息外泄”……**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/z7xPqlc0GbB7ShHeKEtRTfattkj7T3bsyPnz68QvJ6lPVg7SFgrY5pYtEibJiao9WGNWEfmGicicWib041MYnu64GOA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
  
  
  
  
  
  
  
  
