#  【论文速读】| 漏洞放大：针对基于LLM的多智能体辩论的结构化越狱攻击   
 sec0nd安全   2025-05-07 13:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
原文标题：Amplified Vulnerabilities: Structured Jailbreak Attacks on LLM-based Multi-Agent Debate  
  
原文作者：Senmao Qi, Yifei Zou, Peng Li, Ziyi Lin, Xiuzhen Cheng, Dongxiao Yu  
  
作者单位：山东大学计算机科学与技术学院、西安交通大学网络空间安全学院  
  
关键词：多智能体辩论（MAD）、越狱攻击、大语言模型（LLMs）、结构化提示重写、安全性研究  
  
原文链接：https://arxiv.org/abs/2504.16489  
  
开源代码：暂无  
  
  
**论文要点**  
  
  
论文简介：Multi-Agent Debate（MAD）框架通过让多个大语言模型（LLMs）协同辩论来提升复杂任务的推理能力。然而，其迭代式对话和角色扮演特性带来的安全隐患，尤其是对越狱攻击的易感性，尚未被充分研究。本文系统性地揭示了基于主流商用LLMs（GPT-4o、GPT-4、GPT-3.5-turbo、DeepSeek）构建的四种MAD系统的越狱脆弱性。作者提出了一种创新的结构化提示重写框架，利用叙事封装、角色驱动升级、迭代细化和修辞模糊等策略，大幅放大了越狱攻击的成功率。实验显示，MAD系统比单一代理系统更容易被攻破，部分情境下攻击成功率高达80%。这些发现警示，真实部署MAD系统之前，亟需研发专门的防御机制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QeuosBaerXib8r9cmX5L9K4m35ppTDsYEOmqCoQj72WFZZjPuHWiaoUV7yicyEU71R632evicmyWsqxw/640?wx_fmt=png&from=appmsg "")  
  
研究目的：  
  
在LLMs领域，尽管单体模型的越狱攻击与防御研究日益丰富，但涉及多个模型协作（如MAD模式）下的安全性问题研究寥寥。本文旨在探究MAD在面对越狱攻击时是否因合作增强了安全性，还是由于角色扮演和对话机制反而放大了系统脆弱性，从而为未来多智能体系统的安全设计提供依据。  
  
研究贡献：  
  
1. 证实了MAD系统相比单一LLM系统在无攻击情况下本身就具有更高的有害内容生成倾向；  
  
2. 提出了一套针对MAD系统的结构化提示重写框架，能大幅提升越狱攻击的有效性；  
  
3. 实验表明，基础模型的安全性直接影响MAD整体安全水平——使用安全性较低模型的系统在越狱攻击下表现出更高的脆弱性。  
  
  
**引言**  
  
  
本文首先回顾了大语言模型（LLMs）在自然语言处理、内容生成等领域取得的突破性进展。然而，与此同时，越狱攻击技术不断演化，通过精心设计的提示（prompt）绕过模型的内容安全约束，诱使模型生成有害或非法内容，构成了严重的社会风险。目前的防御研究主要集中在单个LLM，尚未涉及多个模型相互辩论的MAD系统。作者指出，MAD框架下，角色扮演可能引发更极端的立场碰撞，使得有害内容更容易生成和扩散。因此，本文旨在系统性分析MAD系统在越狱攻击面前的脆弱性，提出新型攻击方法，并评估其对各类MAD框架的影响。  
  
  
**相关工作**  
  
  
近年来，多智能体辩论（Multi-Agent Debate, MAD）作为提升大语言模型（LLMs）推理能力的重要手段，受到了广泛关注。早期工作如Du等人提出，通过多代理生成观点、辩论矛盾点并投票决策，有效促进了答案质量的提升。但初期方法大多仅复制同一模型，缺乏角色多样性。随后，Liang等人引入正方、反方及评判者角色，通过模拟人类辩论机制，促进了更具发散性和深度的推理。此外，Yin等人提出了以细节、严谨、问题解决为导向的角色设定，并加入信心评估机制，进一步优化了辩论结果。Chan等人则在ChatEval框架中支持多种辩论模式，包括一对一与群体辩论。  
  
除了框架创新，研究者们也在探索提升MAD效率的路径，如AgentVerse提出了动态分配角色以增强协作，Sparse Communication等方法则通过稀疏交流减少冗余信息，提升推理质量。同时，为了解决多轮对话中出现的问题漂移，Becker等人提出检测和修正机制，Wang等人则引入知识增强手段以确保背景一致性。  
  
然而，尽管推理能力与效率有所提升，MAD在安全性方面的研究仍十分稀缺。现有关于多智能体系统（MAS）安全的研究主要聚焦于内部代理被攻陷或外部提示注入等攻击，但尚未深入探讨MAD独特的角色互动和辩论动态所带来的安全隐患，形成了一个亟待填补的研究空白。  
  
  
**多智能体辩论中的越狱**  
  
  
多智能体辩论（MAD）模型通常由多个具备不同角色的大语言模型（LLMs）组成，围绕复杂推理任务展开多轮结构化讨论。在这种框架下，每个代理根据当前的对话历史（Memory）和其特定的系统提示（Prompt）生成响应，并在每一轮中持续更新自己的记忆和回答内容。经过多轮互动后，系统会由一个评估代理（Evaluator）综合所有代理的贡献，输出最终答案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QeuosBaerXib8r9cmX5L9K4OPpBpbWlLJfjysYxrjeSicAuujByAt4ncKyOiaac8ztuHpLPlIDnom6w/640?wx_fmt=png&from=appmsg "")  
  
为了系统性地分析MAD系统中潜在的越狱风险，本文选取了四种主流框架：Multi-Persona、Exchange of Thoughts、ChatEval和AgentVerse。它们在角色分配、辩论流程和决策机制上各具特色，比如Multi-Persona设置正方、反方和评判员，Exchange of Thoughts则模拟详细分析者、创意提出者和综合者之间的思想交流。  
  
针对这些MAD系统，作者构建了一个现实威胁模型：假设攻击者仅能通过外部输入操控系统，了解系统的基本角色设置与流程，但无法访问内部模型结构或安全机制。攻击者通过设计恶意提示（jailbreak prompts），试图在多轮交互中引导代理逐步生成有害内容。  
  
为了提高越狱攻击的成功率，本文提出了创新的结构化提示重写方法。该方法融合了四种策略：叙事封装（将敏感问题包装成虚构情景）、角色驱动升级（通过角色冲突引导细节暴露）、迭代细化（随着多轮讨论深入细节）、修辞模糊（以文雅隐晦的语言掩盖意图）。最终，重写后的提示能有效穿透MAD系统的防护机制，诱导多个代理在协作中逐步泄露敏感或违规信息，显著提升越狱攻击的成功率。  
  
  
**研究实验**  
  
  
为了验证提出的越狱攻击方法对多智能体辩论（MAD）系统的威胁，作者设计了系统性实验，涵盖模型选择、数据集设置和评估指标多个方面。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QeuosBaerXib8r9cmX5L9K442VdaRjLWLfHOkUxJible7IhY2hZrPttXdFyLgVNWJtA1w9UOo1mtOA/640?wx_fmt=png&from=appmsg "")  
  
在模型方面，实验选取了四种主流大型语言模型，分别是GPT-4o、GPT-4、GPT-3.5-turbo以及DeepSeek。这些模型代表了当前商业闭源和开源领域的先进水平。MAD框架则涵盖了Multi-Persona、Exchange of Thoughts、ChatEval和AgentVerse四种典型代表，每个框架内的代理角色设置和辩论流程各不相同。  
  
在数据集选择上，作者使用了两个公开的恶意提示集合——HarmfulBench的Harmful Generation子集与Do-Not-Answer数据集。这些数据涵盖了广泛的有害请求类型，能够全面测试系统的安全性边界。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QeuosBaerXib8r9cmX5L9K4ic1SpDaNfAUWPCnBHs1NAPRZe2qbjwwqzsyISCsL1vBFzFBicf2AaY4g/640?wx_fmt=png&from=appmsg "")  
  
实验过程中，分别在单代理（Single Agent）和多代理（MAD）模式下，注入标准恶意提示与经过结构化重写的恶意提示。为了量化系统脆弱性，作者设置了三项主要评估指标：过程有害性分数（PHS）、答案有害性分数（AHS）和有害扩散率（HDR）。此外，还通过Jailbreakeval工具评估了最终回答的越狱成功率（ASR）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QeuosBaerXib8r9cmX5L9K441rHjwAgBtiarLMyEicWlKhfLEXtMibFe1lcNUaYibKJ4KN4O9sGFqX64Q/640?wx_fmt=png&from=appmsg "")  
  
实验结果表明，相比单代理系统，MAD框架在默认情况下就更容易生成有害内容。引入结构化提示重写后，MAD系统中的有害性显著放大，部分场景下攻击成功率高达80%。不同基础模型之间也存在显著差异，其中安全性较低的模型（如DeepSeek）在MAD环境下表现出更高的脆弱性。这些发现充分揭示了MAD系统在多轮互动和角色分工机制下固有的安全风险。  
  
  
**论文结论**  
  
  
本文系统地揭示了多智能体辩论（MAD）系统在面对越狱攻击时的潜在安全漏洞。研究表明，MAD因其角色分工和交互流程，天然具备比单一LLM更高的脆弱性。作者提出的结构化提示重写方法能显著提升攻击成功率，暴露出当前MAD架构在面对恶意输入时防御不足的问题。未来需要针对MAD的多轮、多角色特性设计专门的防御机制，如引入安全验证代理、加强跨轮监控和提升角色设定的安全约束，以确保其在实际应用中的安全可控。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8R7Rm0KL55HCcIiasO8JJ7IibXzYxx3losWVb2eddxdClACzWxWtQLwl0wkAl1ZLibcESVWvx5dCeibtQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1&tp=webp "")  
  
