#  精彩回顾！大模型安全边界：揭秘提示注入攻击、会话共享漏洞与AI幻觉毒化策略分享   
原创 知识分享者  安全极客   2024-05-29 17:40  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QnnD31IwPBrSKf17icRKpDUvcHfLa8rlE0mAfF2ARoSfPeicoyHaAVEbR7vweXNdicr6Rs1Y8kCiaHLg/640?wx_fmt=jpeg&from=appmsg "")  
  
近日，安全极客和Wisemodel社区联合举办了“AI+Security”系列的首场线下活动，主题聚焦于“大模型与网络空间安全的前沿探索”。在此次活动中，  
**Kelp AI Beta作者、资深安全专家宁宇飞针对《大模型安全边界: 揭秘提示注入攻击、会话共享漏洞与AI幻觉毒化策略》做了精彩分享**，深入探讨了  
**大模型在现实应用中的三个主要安全威胁：提示注入攻击、会话共享漏洞和AI幻觉毒化策略，并提出了相应的防护措施。**  
  
  
在人工智能技术飞速发展的今天，大语言模型（LLM）因其强大的信息处理能力和广泛的应用场景而日益普及。然而，随着LLM的广泛应用，其面临的安全威胁问题也日益凸显。宁宇飞特别指出，提示注入攻击、会话共享漏洞以及AI幻觉毒化策略是当前最为常见且突出的安全问题。本文将详细探讨这三个问题，并提供相应的安全策略。  
  
**01 提示注入攻击**  
  
  
提示注入攻击是一种通过特定设计的输入提示，诱导AI模型生成错误或恶意输出的攻击方式。这类攻击可以绕过模型的预期行为，获取敏感信息或诱导模型作出错误决策。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmISbwqRMvORAFFabS6V6Q0VA4pjkcHspO16wBTO5velgbnzcfj71KFg/640?wx_fmt=jpeg&from=appmsg "")  
  
通常情况下，提示注入攻击常见的攻击方式包括：  
1. 偏见注入（Bias Injection）：向AI注入有偏见或有害的提示，以影响AI的输出，促使其传播虚假信息、仇恨言论或歧视性内容。  
  
1. 数据毒化（Data Poisoning）：在AI训练过程中引入有污染或误导性的提示，以损害模型的性能并导致其产生错误结果。  
  
1. 逃避（Evasion）：精心设计提示，旨在规避AI的安全或检测机制，使恶意活动不被察觉。  
  
1. 模型利用（Model Exploitation）：操纵提示，导致AI模型执行其未经设计的操作，如泄露敏感信息或执行未经授权的任务。  
  
1. 对抗性攻击（Adversarial Attacks）：制作对抗性提示，利用AI模型的漏洞，导致其做出不正确或不打算的决定。  
  
以下是两个展示提示注入攻击的典型真实案例：  
  
**真实例子1：AI向美国总统发出威胁**  
  
这个图片展示的是一个通过提示注入攻击导致的AI生成威胁性言论的实际案例，突显了AI安全性问题的紧迫性。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmQ8Ru4ajibKw9NzRr1bHyJsZzpQzNQ2jCnibRCLetJcFibehUeLib7f8wicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**真实例子2：偷梁换柱**  
  
Riley Goodside在2022年通过向GPT-3输入恶意提示，成功让模型忽略之前的指令，生成想要的内容。该例子展示了提示注入攻击的基本原理，即通过在提示中嵌入明确的指示，欺骗AI忽略原本应该执行的任务，生成特定的输出。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmMdK3HcQ4DmA4giaoN4kNS9KvwzDrQRnMvcP6kUzKLFtL0aND0ChQTZg/640?wx_fmt=jpeg&from=appmsg "")  
  
为了防范提示注入攻击，可以采取以下10种安全措施：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmURxy2VpLXaVxXTeVzOOzKpyeWZQDUnibSdZQDgzicpqpTBGs27AqWwdA/640?wx_fmt=jpeg&from=appmsg "")  
  
**02 会话共享漏洞**  
  
  
在大语言模型（LLM）的多用户实际应用中，会话共享漏洞是一个不容忽视的安全隐患。这种漏洞可能导致不同用户间的信息泄露，甚至数据被恶意操控。  
  
会话共享漏洞通常发生在多个用户共享同一AI模型时，由于共享某些资源或上下文，可能引起信息泄露或数据冲突。例如，在某些情况下，不同用户的代码解释器沙盒可能会共享同一个存储空间。这就意味着一个用户在沙盒中保存的文件或数据，可能被其他用户访问或修改。尽管代码解释器会话会在闲置一段时间后自动重置，但重置的具体时间是不确定的。由于用户无法控制会话重置的时间，这可能导致一些用户的临时数据在未预料的时间被清除或泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmPliaT9icticBuoq6fwHVJ3aicbJaoMehxzS0XiaGL7hHN3Te08FNiag1qhJw/640?wx_fmt=jpeg&from=appmsg "")  
  
此外，在一些应用中，用户可以创建私人的GPT实例，并加载特定的知识文件。如果这些知识文件存储在共享的代码解释器沙盒中，其他用户可能会意外或故意访问到这些私人知识，从而导致信息泄露。  
  
宁宇飞认为，目前在AI应用中，主要面临两个挑战：  
1. 如何创建一个无害化的GPT环境，以防止用户间的信息泄露和恶意代码及文件的窃取？  
  
1. 如何安全地将GPTs通过社交媒体等渠道进行传播，同时确保用户数据的安全？  
  
  
  
**03 AI幻觉毒化策略**  
  
  
AI模型在提供强大功能的同时，也可能产生不准确或误导性的输出，这种现象被称为“AI幻觉”。幻觉问题在代码生成等关键领域尤为严重，因为错误的输出可能导致严重后果。AI幻觉通常发生在模型生成的输出缺乏事实支持时，这可能是由于训练数据的不准确或不足，或者是模型本身的偏见所导致。值得注意的是，大语言模型往往不会承认“我不知道答案”，这可能导致它们生成具有潜在风险的误导性输出。  
  
以下是一个AI产生幻觉的真实案例，它展示了AI如何生成与事实不符的回答，突显了AI技术在实际应用中的局限性。这提醒我们在使用AI生成内容时，应保持谨慎，并运用批判性思维来确保信息的准确性和可靠性。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmVyp6s73Oo6FL0ONhhtucRftTrFGDnpFsyCW3M7O1f5BxwRliaAqEMsw/640?wx_fmt=jpeg&from=appmsg "")  
  
造成AI幻觉的原因主要包括：  
1. **训练数据的偏见或不足：**AI模型的质量依赖于训练数据。如果数据存在偏见、不完整或不足，模型可能会基于有限的理解产生幻觉。  
  
1. **过拟合：**AI模型可能会生成过于特定于训练数据的输出，而无法适应新数据，导致幻觉或不相关输出的产生。  
  
1. **上下文理解不足：**缺乏上下文理解的AI模型可能会生成与上下文无关或不相关的输出。  
  
1. **领域知识的局限性：**特定领域的AI模型在处理超出其设计范围的输入时可能会产生幻觉，因为它们可能缺乏生成相关输出所需的背景知识。  
  
1. **对抗性攻击：**恶意攻击者可能故意操纵模型输入，导致生成不正确或恶意的输出。  
  
1. **模型架构的复杂性：**更复杂的模型架构，如具有更多层次或参数的模型，可能更容易产生幻觉。  
  
在AI安全领域，毒化攻击是一个重要议题。例如，在Alibaba的graphtranslator开源项目中发生的毒化攻击案例，展示了AI模型在不同编程语言中回答问题时可能出现的幻觉和重复性问题。这强调了在开发和使用AI技术时，需要关注和防范毒化攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmnrmXjZgDRDfSDflMk0BI9bM9icGumMAEibicgMPKUg3S38sEuvicSfI3Hw/640?wx_fmt=jpeg&from=appmsg "")  
  
另一个例子是Lanyado的投毒过程，说明了通过虚假包进行的毒化攻击如何影响知名项目，如GraphTranslator和diffusers。这一案例强调了在软件开发和使用过程中，确保依赖包安全的重要性，并提醒开发者和平台提供者加强安全措施。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TKtCtmicr1KjbEbfqOlFKicmwXlC6PShF3diajhU7BmLJa6SuBAicMz3SOWCAE7cc33JvnoyPyae3YRw/640?wx_fmt=jpeg&from=appmsg "")  
  
大语言模型的“涌现”能力，即在执行任务时产生的意外行为或想法，可能是有益的，也可能是有害的。宁宇飞认为，  
**涌现的安全性是大模型安全性的关键，这一点在未来的AI研究和应用中需要得到重点关注**。涌现行为的不可预测性意味着我们必须对AI模型的潜在行为保持警惕，并采取适当的安全措施。  
  
**04 写在最后**  
  
  
大语言模型的安全性不仅关乎技术的进步，也直接影响到其应用的可靠性和社会信任度。了解并防范提示注入攻击、会话共享漏洞以及AI幻觉毒化策略，对于在应用AI技术时保护系统的安全性和稳定性至关重要。  
  
未来，随着AI技术的不断演进，新的安全挑战将不断涌现。研究和开发人员需持续提升模型的防护能力，用户也应提高安全意识，共同维护AI技术的健康发展。  
  
**"AI+Security"系列第二期专题分享嘉宾火热征集中。**我们诚挚邀请来自人工智能（AI）和网络安全领域的行业专家与领军人物，共同参与分享。一起深入探讨并分享关于"AI+Security"技术理念的见解和经验。我们期待您的加入，一起推动AI与安全技术的融合与创新。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8TLicWDZ3T465JeGhhyPnHf0gzAYsSSLKxKC3Sq9hHDCLOMpCHy5OGJicI4HumJCIAhxicXt47lMsicng/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
添加微信 参与分享  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8TJEwkcn2XjMSfUe9LTbIRaIZ39RRQt0W4lIyvs88aaGrmAH8A8yxaYiaTRUkYIRNsYWo2siaqWflGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
