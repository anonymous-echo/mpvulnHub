#  ChatGPT在漏洞管理中的创新应用   
原创 周文权  数缘信安社区   2025-01-25 23:02  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sSglg2t6pLdZIr613OsUegUoUoC6kcfUauwV5QhQsNoMnznp9bDLTjSuHtZuUBicjbKEyqKJ2LhlU9mLqd70L8w/640?wx_fmt=jpeg "")  
  
**ChatGPT能直接执行**  
  
**多样化的漏洞管理任务吗？**  
  
  
  
  
  
**撰文** | 周文权  
  
**编辑** | 刘梦迪  
  
  
**一、背景介绍**  
  
  
随着人工智能技术的快速发展，大型语言模型（LLMs）如ChatGPT在代码分析领域引起了广泛关注。ChatGPT展示了处理基础代码分析任务的能力，例如生成抽象语法树，这表明它有潜力理解代码语法和静态行为。然而，ChatGPT是否能够完成更复杂的实际漏洞管理任务，如下图所示漏洞管理过程中的预测安全相关性和补丁正确性，这一点尚不清楚。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfU3Mr71CDibhPZEibhciaOGEBQRyfRU8nLH7hOq2Fa4ubGia36zSyxI92BVw/640?wx_fmt=png "")  
  
漏洞管理过程  
  
  
来自浙江大学的刘君茗，王文海等人在USENIX Security 2024上探讨了ChatGPT在涉及完整漏洞管理过程的6个任务上的能力，任务包括：软件缺陷报告标题生成、安全缺陷报告预测、漏洞严重性评估、漏洞修复、补丁正确性评估和稳定补丁分类。作者使用的数据集如下图所示，其研究的主要问题是：ChatGPT是否可以直接协助软件维护者在漏洞管理过程中执行多样化的任务？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfU2KDeRuS074urV3jzPU4LHdLdvEQguaNjaUPRW3nI7JaoWUNrXZEumw/640?wx_fmt=png "")  
  
数据集  
  
  
**二、方法与理论**  
  
  
作者采用了大规模数据集，包含78,445个样本，对ChatGPT进行了六个漏洞管理任务的评估。对于每个任务，研究者比较了ChatGPT与当前最先进的方法（SOTA），并调查了不同提示的影响。评估流程包括三个阶段：模板设计、最佳模板选择和大规模评估。研究者手动设计了基于现有策略的提示模板，并在训练数据集上进行了评估和完善。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfUYnMSFyDpr6lKeQT55GYHzFyFgoz5E0UyKFuoDo9gvS1dw1fz0xW0LQ/640?wx_fmt=png "")  
  
评估流程  
  
  
作者的研究基于以下理论：  
- 漏洞管理过程：涉及识别、分类和缓解软件产品中的漏洞。  
  
- ChatGPT和提示：ChatGPT是一个人工智能聊天机器人，通过提示（输入）来训练，以提供类似人类的回应。  
  
  
此外，作者还提出了一种新的提示模板，通过让ChatGPT从示例中提取专业知识，并将其整合到提示中，以提高性能。提示模板如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfUdXrJHyN456eVpv60SOVItXPKBw2USbyHWAibh5jawv0TLFbnXxY6CBQ/640?wx_fmt=png "")  
  
提示模板  
  
  
一个具体的示例如下图所示，其中粉色的便是作者添加的专业知识，其与一般信息提示不同，它提供了安全错误报告的特征，在这个示例中，作者指导ChatGPT应将内存泄漏视为安全错误。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfUZRCBEEbelgKV3ibLHPNYqpqf6W0rhxv7a6NzB6uRDULe9KkT2RgqI8Q/640?wx_fmt=png "")  
  
expertise提示词示例  
  
  
**三、实验与结果**  
  
  
作者使用的数据集包含11个SOTA方法的78,445个样本，总计27,284,148个标记，并使用了多个评估指标，包括ROUGE-1、ROUGE-2、ROUGE-L、召回率、精确率、F1分数和AUC值。主要结果如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfUlrwQia3Crnf3oAtHIBlI5yiaN5ic5LnjdR8vk3PtnhRbTjqJudGeZaWmw/640?wx_fmt=png "")  
  
实验结果  
  
  
结果表明：ChatGPT在某些任务上的表现超过了SOTA方法，尤其是在与软件文档处理相关的任务上；提示模板对ChatGPT的性能有显著影响，其中自我启发式提示在某些任务上表现突出；ChatGPT可能误解和误用提示中的信息，有效地指导ChatGPT关注有用信息而不是无关内容仍然是一个开放的问题。  
  
  
**四、讨论与启示**  
  
  
作者的实验结果表示：  
- ChatGPT在没有专门训练的情况下，就能在一些漏洞管理任务上达到或超过SOTA方法。  
  
- 精心设计的提示对于提高ChatGPT的性能至关重要。  
  
- 提供过多的信息可能会导致ChatGPT的误解和滥用。  
  
但是，作者的研究主要关注ChatGPT在特定任务上的表现，没有全面评估其在所有漏洞管理任务上的能力，且作者也没有考虑ChatGPT在实际软件工程环境中的集成和应用。此外，尽管ChatGPT在某些任务上表现出色，但在需要深入领域专业知识的任务上可能仍然存在局限性，更重要的是，实验结果表明提示工程是一个关键领域，需要进一步研究如何更有效地设计提示。  
  
  
**总结**  
  
  
在本文中，作者探讨了ChatGPT在六大漏洞管理任务上的应用潜力，并评估了其性能。研究结果表明，ChatGPT在某些任务上能够达到或超过现有的最先进技术，尤其是在处理与软件文档相关的任务时。然而，作者也指出，ChatGPT在理解和应用提示信息方面存在局限性，这表明需要进一步的研究来优化提示设计，以便更好地利用ChatGPT的能力。  
  
  
**参考资料**  
  
  
[1] Liu P, Liu J, Fu L, Lu K, Xia Y, Zhang X, Chen W, Weng H, Ji S, Wang W. Exploring ChatGPT's Capabilities on Vulnerability Management[C]. 33rd USENIX Security Symposium, USENIX Security 2024, Philadelphia, PA, USA, August 14-16, 2024.  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sSglg2t6pLdZIr613OsUegUoUoC6kcfUCH2tfdmYFXgoXljbZgibEPek8k2C1OEazS4DKXhb0LNMPffGicHxrjkg/640?wx_fmt=png "")  
  
  
  
  
  
  
**往期精彩文章推荐**  
  
  
  
  
- [针对32位设备上Ascon密码算法的侧信道模板攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTUyODMwNA==&mid=2247493991&idx=1&sn=092816a20934c4aafc0dde1c36b7506d&scene=21#wechat_redirect)  
  
  
  
  
- [一种基于内容查询的口令窃取侧信道分析](https://mp.weixin.qq.com/s?__biz=MzI2NTUyODMwNA==&mid=2247494041&idx=1&sn=7a5fb774ec932575a74bf97b188a3e46&scene=21#wechat_redirect)  
  
  
- [一种针对FLASH擦除过程的故障注入攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTUyODMwNA==&mid=2247494084&idx=1&sn=269335d5adb370e2e2b32d4ef3ef94cc&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZPwe5TesXJDBCQRM6LTJHRibMkjqsv8foXmicVnFVp9LOiaNP9QlMcHmvmIKscpNadVroiaSdwcibKzp3uMVZAr1Gvw/640?wx_fmt=png "")  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sSglg2t6pLfFHpo3axvjIIWfW86w5ib4j9iaIgPZEr41uxXbrewtLcVvukicTxNym8Btibe9g8PPD4OwYUWdibl4RQw/640?wx_fmt=jpeg "")  
  
  
