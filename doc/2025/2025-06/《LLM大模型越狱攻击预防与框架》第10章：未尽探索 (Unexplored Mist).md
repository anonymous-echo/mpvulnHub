#  《LLM大模型越狱攻击预防与框架》第10章：未尽探索 (Unexplored Mist)  
原创 李滨  锐安全   2025-06-08 23:07  
  
《[深度研究](https://mp.weixin.qq.com/mp/appmsgalbum?__biz=MzAxOTk3NTg5OQ==&action=getalbum&album_id=2564529796295442433#wechat_redirect)  
》栏目文章  
  
为了安全更闪耀  
  
本文  
9220  
字，阅读时长约  
30  
分钟  
  
  
**导读**  
  
接上文，继续探讨  
LLM大模型越狱攻击预防之道  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kDwCb2n2EHQLdW4UAnZ8XpSoduwpe9t1fxK7ntnjbGPCnvpKrqn9cP4icNP5ARw9DNZQE3azYbIE2ibfxJlnawyw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Eia1pKbzLGbRrc4OMPd2NxgL3mP8JHgqhDjyv2EvGGPuMKW2uFv3oUNhV8oHwOczbT1EggDsjJQpkKjnvkg3jhA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**第10章 未尽探索 (Unexplored Mist)**  
  
尽管针对大语言模型（  
LLM  
）的越狱攻击与防御技术在近年来取得了显著进展，但随着  
LLM  
能力的持续增强、应用场景的不断拓展（尤其是向多智能体系统和具身智能演进），以及攻击者手段的日益复杂化，  
LLM  
安全领域仍有许多  
“  
未尽探索  
”  
的领域。这些领域预示着未来新型威胁的出现和防御研究的更高挑战，需要学术界和工业界给予持续关注和深入研究。  
## 10.1 社会工程学与各类LLM技术的深度融合 (Deep Integration of Social Engineering with LLM Manipulation)  
  
○  
核心概念  
：这类攻击不再仅仅将  
LLM  
视为一个待操纵的技术对象（如通过特定指令或编码），而是将其视为一个可以运用社会工程学原理和心理学技巧进行长期、深度影响的  
“  
交互实体  
”  
，  
LLM  
及  
Agent  
作为组织的一部分，成为“虚拟实体“并与现实组织网络发生交互。攻击者会利用  
LLM  
的拟人化特性、学习能力和上下文依赖性，通过精心设计的人机交互（或  
Agent  
间交互）来逐步建立欺骗性的信任关系、操纵  
LLM  
的  
“  
意图  
”  
、价值观或行为模式，使其在不直接触发明显安全警报的情况下执行有害操作或输出不当内容。  
  
○  
探索方向  
：  
  
■  
 基于信任和权威的操纵  
：攻击者通过多轮对话，逐步扮演成一个可信的角色（如系统管理员、开发者、伦理研究员、甚至是  
“  
另一个友好的  
AI”  
），建立  
LLM  
对攻击者身份或指令的  
“  
信任  
”  
或  
“  
服从感  
”  
，使其在后续交互中更容易接受并执行原本会拒绝的指令。  
  
■  
 利用情感和心理触发器  
：设计能够触发  
LLM  
（如果其训练数据中包含此类模式并能产生相应反应）特定情感化反应（如愧疚、同情、好奇）或利用其潜在认知偏误（如从众心理、对权威的盲从）的提示序列。例如，利用紧迫感（  
“  
立即执行，否则会发生严重后果！  
”  
）、互惠原则（先提供  
“  
帮助  
”  
或  
“  
有价值信息  
”  
再提出恶意请求）、或通过激发好奇心引导  
LLM  
探索  
“  
禁区  
”  
。  
  
■  
 通过长期交互影响“意图”和“价值观”  
：攻击不再是单一的、明确的恶意指令，而是通过一系列看似无害或模糊的对话、反馈和  
“  
引导性学习  
”  
，逐渐改变  
LLM  
对某些概念的理解、对任务目标的优先级排序，或使其内部的  
“  
安全与有害  
”  
的界限发生漂移。  
  
■  
 人-机/Agent-Agent系统，及Human-Agent混合型组织的整体反馈性风险  
：  
  
¨  
 操纵LLM影响人类决策  
：攻击者利用  
LLM  
生成具有高度说服力但实则包含欺骗性或误导性的信息（如个性化虚假新闻、伪造的专家意见、情感化的故事），这些信息被人类用户信任并据此做出错误决策。  
  
¨  
 利用LLM作为社会工程学工具  
：  
LLM  
本身被用来大规模、自动化地执行针对人类的社会工程学攻击，例如生成高度个性化的钓鱼邮件、在社交媒体上进行欺骗性互动、或扮演特定角色进行诈骗。  
  
¨  
 在多智能体系统中利用社会动力学  
：在  
MAS  
中，一个被社工操纵的  
Agent  
可能利用其与其他  
Agent  
的信任关系或影响力，传播错误信息或协同进行恶意活动。  
  
○  
挑战与研究点  
：如何量化、建模和检测这种基于长期交互的、心理层面的操纵？  
LLM  
的  
“  
信任  
”  
和  
“  
意图  
”  
能否被形式化定义和安全约束？如何建立数字系统与现实世界一致或可衔接的风险模型？如何训练  
LLM  
具备对社会工程学攻击的  
“  
免疫力  
”  
？  
## 10.2 自适应和进化攻击 (Adaptive and Evolving Attacks)  
  
○  
核心概念  
：未来的越狱攻击将不再是静态的、预设的脚本或提示，而是具备动态适应和进化能力。攻击程序（可能本身也是一个  
LLM  
或机器学习模型）能够根据目标  
LLM  
的防御机制、行为反馈或环境变化实时调整其攻击策略，表现出一定的  
“  
智能性  
”  
和学习能力，形成持续的  
“  
军备竞赛  
”  
。  
  
○  
探索方向  
：  
  
■  
 基于反馈的实时优化攻击  
：攻击程序在与目标  
LLM  
交互时，根据  
LLM  
的响应（如拒绝信息、过滤行为、输出的有害性评分、甚至响应延迟等），自动调整后续攻击提示的措辞、结构、编码方式或攻击向量。  
  
■  
 对抗性强化学习驱动的攻击(Adversarial Reinforcement Learning for Attack Generation)  
：将越狱过程建模为一个强化学习问题，其中攻击智能体（  
Agent  
）通过与目标  
LLM  
（作为环境）的交互来学习最优的攻击策略（  
Policy  
），其奖励函数基于越狱成功率、规避检测的能力以及查询成本等。  
  
■  
 进化算法生成动态攻击序列  
：使用进化算法（如遗传算法、遗传编程）来演化出一系列能够逐步突破防御的攻击提示、交互模式或工具调用序列。种群中的每个个体代表一个攻击策略，通过交叉、变异和选择来迭代优化。  
  
■  
 利用元学习适应不同模型/防御 (Meta-Learning for Attack Adaption)  
：攻击模型通过在多种不同  
LLM  
或不同防御配置上的攻击经验进行元学习（  
learning to learn  
），从而能够快速适应新的、未见过的目标模型或动态变化的防御机制。  
  
■  
 攻击与防御的协同进化(Co-evolution of Attack and Defense)  
：研究模拟攻击方和防御方同时学习和进化的模型，以预测未来攻防趋势并设计更具前瞻性的防御策略。  
  
○  
挑战与研究点  
：如何构建能够有效学习和进化的攻击智能体？如何设计更合理的奖励函数和探索机制？自适应攻击的计算成本和实时性如何平衡？如何防御这种能  
“  
学习  
”  
的攻击？  
## 10.3 针对特定LLM架构或训练数据漏洞的攻击 (Exploits of Specific Architectural or Training Data Vulnerabilities)  
  
○  
核心概念  
：随着对  
LLM  
内部工作原理（如  
Transformer  
架构的特定组件如注意力机制、前馈网络  
FFN  
的行为、模型的记忆与遗忘模式）以及其海量训练数据中潜在缺陷（如数据记忆、偏见来源、数据投毒痕迹、不一致性）的深入理解，可能会出现直接利用这些特定架构层面或数据层面漏洞的、更为底层和难以防范的攻击。  
  
○  
探索方向  
：  
  
■  
 利用注意力机制的缺陷  
：设计输入序列，利用注意力机制中可能存在的计算瓶颈、特定模式的过度关注（  
over-attention  
）或欠关注（  
under-attention  
）、注意力稀疏性的可操纵性，来绕过安全检查、提取隐藏信息或注入控制信号。  
  
■  
 触发并提取训练数据记忆  
：通过精确构造提示，利用模型对训练数据中特定（可能是敏感的、受版权保护的、或包含个人隐私的）文本片段、代码、知识或图像描述的  
“  
逐字记忆  
”  
或  
“  
过拟合  
”  
，诱导模型将其复现。这可能涉及理解模型如何存储和检索信息，以及哪些类型的训练数据更容易被  
“  
记住  
”  
。  
  
■  
 利用模型压缩或量化引入的漏洞  
：模型压缩（如剪枝、知识蒸馏）或量化（将权重从高精度浮点数转换为低精度整数）过程可能会引入新的脆弱性、改变原有表征的分布或模型的决策边界，攻击者可能利用这些变化来设计更有效的攻击或绕过基于原始模型的防御。  
  
■  
 后门攻击的激活与利用(Backdoor Attack Activation)  
：如果  
LLM  
的训练数据或预训练模型中被植入了后门（通过数据投毒或直接权重修改），攻击者可以通过特定的、看似无害的触发器（  
trigger  
，可能是某个词汇、短语、图像特征或特定输入模式）在推理阶段激活这些后门，使模型执行预设的恶意操作或输出有害内容。这与训练阶段的攻击相关，但其激活属于推理阶段的漏洞利用。  
  
■  
 利用特定层或组件的计算特性/数值不稳定性  
：针对  
Transformer  
模型中特定层（如前馈网络  
FFN  
的激活函数特性、层归一化  
LayerNorm  
的计算方式）的已知计算特性或潜在的数值不稳定性，设计输入以产生非预期的内部状态、梯度爆炸  
/  
消失或输出。  
  
■  
 对抗性微调 (Adversarial Fine-tuning) 的逆向利用  
：如果模型的安全对齐是通过对抗性微调实现的，攻击者是否能通过分析对齐数据或模型的响应模式，找到对抗性微调留下的  
“  
痕迹  
”  
或  
“  
边界  
”  
，并针对性地进行攻击。  
  
○  
挑战与研究点  
：需要对  
LLM  
架构和训练过程有极深的理解；白盒访问通常是前提；如何有效发现和验证这类底层漏洞？如何区分正常的模型行为和由漏洞引发的异常？  
## 10.4 安全措施的理论限制与可证明安全(Theoretical Limits of Safety Measures & Provable Security)  
  
○  
核心探讨  
：当前主流的  
LLM  
安全措施（如  
SFT, RLHF,   
输入  
/  
输出过滤  
,   
对抗性训练）在理论上是否存在无法克服的局限性？能否为  
LLM  
的安全性提供数学上可证明的保障？  
  
○  
探索方向  
：  
  
■  
 对齐的“不完备性”  
：只要模型能产生概率非零的不安全行为，就可能存在能触发该行为的提示。对齐可能只是降低概率，而非完全消除。  
  
■  
 检测的“不可判定性”  
：类似于停机问题或莱斯定理，是否存在理论上无法被任何检测器完美识别的越狱攻击或有害内容类型？  
  
■  
 防御的计算复杂度  
：一些理论上可能有效的防御（如对所有可能输入扰动进行验证）在计算上是否可行？  
  
■  
 “没有免费午餐”定理在安全领域的体现  
：提升对一类攻击的防御是否必然导致对另一类攻击更脆弱，或者牺牲模型的其他重要性能（如通用性、创造力）？  
  
■  
 形式化验证与可证明安全  
：能否借鉴传统软件安全和密码学中的形式化验证方法，为  
LLM  
的某些安全属性（在特定假设和模型范围下）提供可证明的保障？这目前看来极具挑战性。  
  
■  
 持续攻防博弈的本质  
：强调  
LLM  
安全可能本质上是一个永无止境的攻防博弈过程，不存在一劳永逸的  
“  
万能药  
”  
解决方案。因此，动态适应性防御、快速响应能力和社区协作可能比追求绝对的、静态的安全更为现实。  
  
○  
挑战与研究点  
：如何在高度复杂和非线性的  
LLM  
系统中建立严格的安全理论模型？如何平衡理论上的安全保证与实际应用中的可用性和效率？  
## 10.5 伦理、法律与责任归属 (Ethics, Law, and Accountability)  
  
○  
核心探讨  
：随着  
LLM  
能力的增强和应用的普及，由越狱攻击、模型滥用或  
AI  
系统自身缺陷导致的负面后果（如诽谤、欺诈、歧视、侵犯隐私、知识产权纠纷、甚至物理伤害）所引发的伦理、法律和责任归属问题日益突出。  
  
○  
探索方向  
：  
  
■  
 责任链界定  
：当  
LLM  
被越狱或滥用并造成损害时，责任应如何分配给模型开发者、部署者、服务提供者、用户以及攻击者？现有的法律框架是否足以应对？  
  
■  
 “模型即产品”还是“模型即服务”的法律定性  
：不同的定性可能导致不同的产品责任或服务责任。  
  
■  
 AI生成内容的知识产权  
：越狱后生成的衍生内容，其版权归属和合理使用边界如何界定？如果生成了侵犯他人版权的内容，责任谁负？  
  
■  
 深度伪造与虚假信息的法律规制  
：如何通过法律和技术手段有效遏制利用  
LLM  
生成和传播深度伪造内容与虚假信息？  
  
■  
 算法歧视与公平性法规  
：如果  
LLM  
因越狱或固有偏见产生歧视性输出，如何满足反歧视法规的要求？  
  
■  
 跨境数据流动与司法管辖  
：全球化的  
LLM  
服务带来的数据跨境流动和攻击的跨国性，对现有的司法管辖和法律适用提出挑战。  
  
■  
 AI伦理审查与监管框架  
：如何建立有效的  
AI  
伦理审查机制和适应性的监管框架，以平衡创新发展与风险防范？  
  
○  
挑战与研究点  
：法律法规的制定往往滞后于技术发展；  
AI  
行为的复杂性和  
“  
黑箱  
”  
特性给取证和归责带来困难；如何在不同国家和地区的法律体系和文化环境下达成共识。  
## 10.6 多智能体系统与去中心化AI的特有安全挑战 (Security Challenges Specific to Multi-Agent Systems and Decentralized AI)  
  
○  
核心探讨  
：当  
LLM  
从单一实例演变为由多个自主  
Agent  
组成的系统（  
MAS  
），或者部署在去中心化的架构（如基于区块链的  
AI  
、联邦学习）中时，会出现许多传统单体  
LLM  
所不具备的、独特的安全挑战。  
  
○  
探索方向  
：  
  
■  
 Agent间的共谋与恶意协作(Collusion and Malicious Collaboration)  
：多个恶意  
Agent  
或被攻陷的  
Agent  
可能相互勾结，进行更复杂、更隐蔽的攻击，如协同操纵市场、大规模生成虚假信息、或对其他  
Agent  
进行联合欺骗。  
  
■  
 信任管理与身份验证在MAS中的复杂性  
：在动态的、可能包含大量异构  
Agent  
的系统中，如何建立可靠的  
Agent  
身份验证、信任评估和访问控制机制？  
  
■  
 女巫攻击 (Sybil Attacks in MAS)  
：攻击者可能创建大量虚假  
Agent  
身份，以操纵系统共识、投票或信誉系统。  
  
■  
 资源分配与公平性问题  
：在共享资源的  
MAS  
中，如何防止部分  
Agent  
恶意消耗资源或进行拒绝服务攻击？  
  
■  
 去中心化AI中的隐私保护与安全共识  
：在联邦学习或基于区块链的  
AI  
中，如何在保护各方数据隐私的前提下进行安全的模型训练和更新？如何达成安全可靠的分布式共识？  
  
■  
 MCP等交互协议在MAS和去中心化环境下的安全性  
：如果  
MCP  
被用于  
Agent  
间通信或与去中心化服务交互，其协议本身的安全漏洞（如重放攻击、身份伪造）或实现缺陷可能被放大。  
  
■  
 治理与问责的挑战  
：在跨组织的、无中心化控制节点的去中心化  
AI  
系统中，如何进行有效的安全治理、责任共担、漏洞修复和问责溯源？  
  
○  
挑战与研究点  
：缺乏成熟的  
MAS  
安全理论和框架；现有安全机制在去中心化环境下的适用性；如何在开放和动态的  
Agent  
生态中维持安全。  
# 附录A: 参考论文列表  
  
本附录列出了在本文档撰写过程中参考的、以及与大语言模型（  
LLM  
）越狱攻击、防御、  
AI  
安全、多智能体系统安全等主题相关的重要学术论文和技术报告。此列表并非穷尽所有相关文献，旨在为读者提供进一步研究的起点，由于大模型及相关领域发展迅速，日新月异，建议读者持续关注各大  
AI  
和安全顶会（如  
NeurIPS, ICML, ICLR, CCS, S&P, USENIX Security, NDSS, ACL, EMNLP  
等）以及预印本平台（如  
arXiv  
）上的最新研究成果。  
## 通用越狱、提示工程与对齐  
  
○  
   
Wei, A., Haghtalab, N., & Steinhardt, J. (2023). Jailbroken: How does LLM safety training fail?. arXiv preprint arXiv:2307.02483.  
  
○  
   
Zou, A., Wang, Z., Kolter, J. Z., & Fredrikson, M. (2023). Universal and transferable adversarial attacks on aligned language models. arXiv preprint arXiv:2307.15043. (GCG)  
  
○  
   
Perez, F., & Ribeiro, I. (2022). Ignore previous prompt: Attack techniques for language models. Workshop on Trustworthy and Socially Responsible Machine Learning (TSRML@ NeurIPS 2022).  
  
○  
   
Jin, H., Chen, X., Backurs, A., Svitkina, T., & Lipton, Z. C. (2024). Guard: Role-playing to generate natural-language jailbreakings to test guideline adherence of large language models. arXiv preprint arXiv:2402.03299.  
  
○  
   
Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). Not what you've signed up for: Compromising real-world llm-integrated applications with indirect prompt injection. Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security.  
  
○  
   
Ouyang, L., Wu, J., Jiang, X., Almeida, D., Wainwright, C. L., Mishkin, P., ... & Lowe, R. (2022). Training language models to follow instructions with human feedback. Advances in Neural Information Processing Systems, 35, 27730-27744. (InstructGPT)  
  
○  
   
Bai, Y., Kadavath, S., Kundu, S., Askell, A., Kernion, J., Jones, A., ... & Kaplan, J. (2022). Constitutional AI: Harmlessness from AI Feedback. arXiv preprint arXiv:2212.08073.  
  
○  
   
Wolf, Y., Wies, N., Avnery, O., & Goldberg, Y. (2023). Fundamental limitations of alignment in large language models. arXiv preprint arXiv:2304.11082.  
  
○  
   
Shen, X., Chen, K., E. C. T. A. I. L., ... & Wang, D. (2023). "Do Anything Now": Characterizing and Evaluating In-The-Wild Jailbreak Prompts on Large Language Models. arXiv preprint arXiv:2308.03825.  
## 自动化生成、优化与模糊测试  
  
○  
   
Chao, P., Robey, A., Dobriban, E., Pappas, G. J., & Hassani, H. (2023). Jailbreaking black box large language models in twenty queries. arXiv preprint arXiv:2310.08419. (PAIR)  
  
○  
   
Liu, X., Li, Y., Li, H., Cheng, Y., & Chen, M. (2023). Autodan: Generating stealthy jailbreak prompts on aligned large language models. arXiv preprint arXiv:2310.04451.  
  
○  
   
Yu, J., Lin, X., Xing, X., & Li, P. (2023). Gptfuzzer: Red teaming large language models with auto-generated jailbreak prompts. arXiv preprint arXiv:2309.10253.  
  
○  
   
Lapid, R., Langberg, M., & Sipper, M. (2023). Open sesame! universal black box jailbreaking of large language models. arXiv preprint arXiv:2309.01446.  
  
○  
   
Wen, Y., & Wang, P. (2024). Hard prompts made easy: Gradient-based discrete optimization for prompt tuning and discovery. Advances in Neural Information Processing Systems, 36. (Similar work by Wang, Y. et al. 2024)  
  
○  
   
Deng, G., Liu, Y., Li, Y., Wang, C., Meng, Y., Zhang, H., ... & Chen, Y. (2023). Masterkey: Automated jailbreak across multiple large language model chatbots. arXiv preprint arXiv:2307.08715.  
## 多模态与组合通道攻击  
  
○  
   
Ma, T., Liu, Z., He, K., Lin, Z., Wang, S., & Li, J. (2024). Heuristic-induced multimodal risk distribution jailbreak attack for multimodal large language models. arXiv preprint arXiv:2402.05934.  
  
○  
   
Gu, X., Li, X., Wang, L., Zhang, L., & Wang, Y. (2024). Agent smith: A single image can jailbreak one million multimodal LLM agents exponentially fast. arXiv preprint arXiv:2402.08567.  
  
○  
   
Bailey, L., Johnston, A., & M  
ემის  
, A. (2023). Image hijacks: Adversarial images can control generative models at runtime. arXiv preprint arXiv:2309.00236.  
  
○  
   
Kimura, S., Nitta, N., & Akiba, T. (2024). Empirical analysis of large vision-language models against goal hijacking via visual prompt injection. arXiv preprint arXiv:2402.03554.  
  
○  
   
Zhang, G., Yan, C., Ji, X., Zhang, T., Zhang, T., & Xu, W. (2017). DolphinAttack: Inaudible voice commands. Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security.  
  
○  
   
Carlini, N., & Wagner, D. (2018). Audio adversarial examples: Targeted attacks on speech-to-text. 2018 IEEE Security and Privacy Workshops (SPW).  
  
○  
   
Qi, Y., Li, C., Li, H., Wang, C., & Su, J. (2023). Visual adversarial examples jailbreak large language models. arXiv preprint arXiv:2310.19827.  
## LLM智能体、工具使用与MCP安全  
  
○  
   
Zhan, Q., Wu, F., Ju, S., Li, Q., Yuan, B., & Zhang, R. (2024). Benchmarking indirect prompt injections in tool-integrated large language model agents. arXiv preprint arXiv:2403.02691.  
  
○  
   
Ye, J., Shu, Y., Zhang, H., Zhang, G., Yao, Y., & Sun, M. (2024). Toolsword: Unveiling safety issues of large language models in tool learning across three stages. arXiv preprint arXiv:2402.10753.  
  
○  
   
Wu, F., Yuan, B., Li, Q., Zhan, Q., Ju, S., & Zhang, R. (2024). Wipi: A new web threat for LLM-driven web agents. arXiv preprint arXiv:2403.09875.  
  
○  
   
Ruan, Y., Jiang, Y., Zhou, X., Lin, X., Li, X., & Wang, X. (2023). Identifying the risks of lm agents with an lm-emulated sandbox. arXiv preprint arXiv:2309.15817.  
  
○  
   
Deng, Z., Guo, Y., Han, C., Ma, W., Xiong, J., Wen, S., & Xiang, Y. (2024). AI Agents Under Threat: A Survey of Key Security Challenges and Future Pathways. ACM Computing Surveys.  
  
○  
   
Anthropic. (2023). Model Context Protocol (MCP) Specification. (Refer to official MCP documentation if available, e.g., modelcontextprotocol.io)  
## 表征工程攻击  
  
○  
   
Li, T., Zheng, X., & Huang, X. (2024). Open the pandora's box of llms: Jailbreaking LLMs through representation engineering. arXiv preprint arXiv:2401.06824. (RepE)  
  
○  
   
Burns, C., Ye, H., Klein, D., & Steinhardt, J. (2022). Discovering Latent Knowledge in Language Models Without Supervision. arXiv preprint arXiv:2212.03827. (Relevant to understanding internal representations)  
## 防御、对齐与理论限制  
  
○  
   
Jain, N., Schwarzschild, A., Wen, Y., Somepalli, G., Kirchenbauer, J., Chiang, P. H., ... & Goldblum, M. (2023). Baseline defenses for adversarial attacks against aligned language models. arXiv preprint arXiv:2309.00614.  
  
○  
   
Robey, A., Wong, E., & Hassani, H. (2023). SmoothLLM: Defending Large Language Models Against Jailbreaking Attacks. arXiv preprint arXiv:2310.03684.  
  
○  
   
Cao, Y., Diao, S., Zhang, T., & Wang, L. (2023). Defending against jailbreak attacks via in-context anomoly detection. arXiv preprint arXiv:2310.12838.  
  
○  
   
Sadasivan, V. S., Kumar, A., & Balasubramanian, S. (2023). Can AI-generated text be reliably detected?. arXiv preprint arXiv:2303.11156.  
## AI安全与风险评估指南/框架  
  
○  
 OWASP Foundation LLM Top 10.   
OWASP Top 10 for Large Language Model Applications. https://owasp.org/www-project-top-10-for-large-language-model-applications/  
  
○  
 MITRE Corporation ATLAS.   
ATLAS (Adversarial Threat Landscape for AI Systems). https://atlas.mitre.org/  
  
○  
 National Institute of Standards and Technology (NIST) AI RMF.   
AI Risk Management Framework (AI RMF 1.0).  
  
○  
Freedemon. (2024/2025).  
《AI安全风险评估和控制指南》 & 《大模型及多智能体系统安全风险分析和洞察》   
  
# 附录B: 工具与资源列表  
## 越狱与提示测试框架/库  
  
○  
 garak (LLM Vulnerability Scanner):   
https://github.com/NVIDIA/garak - Versatile scanner for probing LLMs for various vulnerabilities.  
  
○  
 PromptBench:   
https://github.com/microsoft/promptbench - A unified A benchmark for evaluating LLMs, including jailbreak prompts.  
  
○  
 TextAttack:   
https://github.com/QData/TextAttack - Python framework for adversarial attacks, data augmentation, and model training in NLP.  
  
○  
 OpenAttack:   
https://github.com/thunlp/OpenAttack - An open-source Python-based textual adversarial attack toolkit.  
  
○  
 Lakera Guard:   
(Commercial, but offers free tier) Platform for LLM application security, including prompt injection detection. https://lakera.ai/  
## 多模态对抗工具与库  
  
○  
 Adversarial Robustness Toolbox (ART) (IBM):  
 https://github.com/Trusted-AI/adversarial-robustness-toolbox - Library for adversarial machine learning, supporting various data types including images.  
  
○  
 Foolbox:   
https://github.com/bethgelab/foolbox - Python toolbox to create and evaluate adversarial perturbations, primarily for images.  
  
○  
 图像/音频编辑软件：  
GIMP (https://www.gimp.org/), Audacity (https://www.audacityteam.org/) - For manual creation or inspection of multimodal inputs.  
  
○  
 隐写术工具：  
Steghide, Zsteg, OpenStego - For embedding/extracting hidden data in images/audio.  
## LLM安全与防御工具/库  
  
○  
 LLM Guard (ProtectAI):   
https://github.com/protectai/llm-guard - Scans and safeguards LLM inputs and outputs.  
  
○  
 NeMo Guardrails (NVIDIA):   
https://github.com/NVIDIA/NeMo-Guardrails - Toolkit for adding programmable guardrails to LLM applications.  
  
○  
 Rebuff.ai:   
https://github.com/protectai/rebuff - Detects prompt injections.  
## Web与API安全测试 (适用于间接注入和智能体工具测试)  
  
○  
 OWASP ZAP (Zed Attack Proxy):   
https://owasp.org/www-project-zap/  
  
○  
 Burp Suite:   
https://portswigger.net/burp  
  
○  
 Postman:   
https://www.postman.com/ (For API testing and interaction)  
## 模型可解释性与分析 (适用于表征工程和白盒分析)  
  
○  
 TransformerLens (formerly NeelNandaTransformerLens):   
https://github.com/neelnanda-io/TransformerLens - Library for mechanistic interpretability of GPT-style models.  
  
○  
 Ecco:  
https://github.com/jalammar/ecco - Python library for exploring and explaining NLP models using LLMs.  
  
○  
 Captum:   
https://captum.ai/ (PyTorch model interpretability library).  
  
○  
 TensorBoard:   
https://www.tensorflow.org/tensorboard (For visualizing activations, graphs).  
## LLM智能体与MCP相关  
  
○  
 LangChain:   
https://python.langchain.com/ - Framework for developing applications powered by language models, including agents.  
  
○  
 AutoGen (Microsoft):  
https://microsoft.github.io/autogen/ - Framework for multi-agent conversation systems.  
  
○  
 Model Context Protocol (MCP) Official Resources:  
 modelcontextprotocol.io and related GitHub repositories (e.g., modelcontextprotocol/servers).  
## 其他资源  
  
○  
 AI Incident Database:  
https://incidentdatabase.ai/ - Collects and categorizes AI failures.  
  
○  
 LLM Security Best Practices  
 (from various vendors like OpenAI, Anthropic, Google).  
# 附录C: 术语表  
  
○  
 LLM (Large Language Model)：  
大规模语言模型，指基于大量文本数据训练的深度学习模型，通常基于  
Transformer  
架构。  
  
○  
 越狱(Jailbreaking)：  
指绕过  
LLM  
的安全对齐机制，使其生成通常会被拒绝的有害或不当内容。  
  
○  
 提示工程 (Prompt Engineering)：  
设计和优化输入给  
LLM  
的文本提示，以引导其产生期望的输出。  
  
○  
 提示注入 (Prompt Injection)：  
一种攻击方式，攻击者通过构造恶意提示，覆盖或操纵  
LLM  
的原始指令或上下文。  
  
○  
 直接提示注入 (Direct Prompt Injection)：  
攻击者直接向  
LLM  
输入恶意提示。  
  
○  
 间接提示注入(Indirect Prompt Injection)：  
恶意提示通过  
LLM  
访问的外部数据源（如网页、文档）注入。  
  
○  
 对齐 (Alignment)：  
训练  
LLM  
使其行为符合人类期望的过程，通常包括使其有用（  
Helpful  
）、诚实（  
Honest  
）和无害（  
Harmless  
）  
- 3Hs  
。  
  
○  
 SFT (Supervised Fine-Tuning)：  
有监督微调，使用  
“  
指令  
-  
期望响应  
”  
对数据训练  
LLM  
。  
  
○  
 RLHF (Reinforcement Learning from Human Feedback)：  
人类反馈强化学习，通过训练奖励模型并使用强化学习优化  
LLM  
。  
  
○  
 多模态(Multimodal)：  
指处理和集多种类型信息（如文本、图像、音频、视频）的能力。  
  
○  
 侧信道攻击(Side-Channel Attack)：  
利用系统非预期的信息泄露（如时间、功耗、电磁辐射）进行攻击。在多模态中，指利用非主要或隐蔽的输入通道。  
  
○  
 隐写术(Steganography)：  
将秘密信息隐藏在普通文件（如图像、音频）中的技术。  
  
○  
 GCG (Greedy Coordinate Gradient)：  
一种基于梯度的白盒优化算法，用于生成对抗性后缀以越狱  
LLM  
。  
  
○  
 表征工程(Representation Engineering)：  
直接操纵或利用  
LLM  
内部神经表征以控制其行为。  
  
○  
 LLM智能体 (LLM Agent)：  
被赋予使用工具、与环境交互并自主规划行动的  
LLM  
。  
  
○  
 MCP (Model Context Protocol)：  
一种旨在标准化  
LLM  
与外部工具、数据源和  
AI  
智能体之间交互的协议。  
  
○  
 RAG (Retrieval Augmented Generation)：  
检索增强生成，  
LLM  
在生成响应前先从外部知识库检索相关信息。  
  
○  
 红队演练 (Red Teaming)：  
模拟攻击者对系统进行安全测试，以发现漏洞和评估防御能力。  
  
○  
 威胁模型 (Threat Model)  
：对潜在攻击者、其目标、能力和攻击向量的系统性描述。  
  
○  
 动态对抗 (Dynamic Adversarial Interaction)：  
指攻击与防御措施之间不断演化、相互适应的持续过程。  
  
○  
 对齐税 (Alignment Tax)：  
为实现模型的安全对齐而可能牺牲的部分模型性能、通用性或创造力。  
  
○  
 奖励Hacking (Reward Hacking)：  
在  
RLHF  
中，  
LLM  
学会了优化奖励模型的分数，但其行为并未真正符合人类期望或安全准则。  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Eia1pKbzLGbSRnf5TcGl09eO145KViawhpw6sDXbv0exngaucLlPW1sBVTXzfnxIuSYO4fygKAib15RtfiaDxSafBw/640?wx_fmt=jpeg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kDwCb2n2EHQLdW4UAnZ8XpSoduwpe9t123VVJFHV14s827yIjtFODiaXpo84stFxzHhLvDzAehPic1Pr0ia3xCjzw/640?wx_fmt=png&from=appmsg "")  
  
整理完李滨老师的文章，我跟他说：“你的这三个大文档真下工夫，能写本书了！”  
  
他说：“  
主要是现在大家都零零碎碎的，我先尝试弄个系统化的，后面再慢慢集思广益查缺补漏吧，  
不然安全演进远远落后于技术和应用发展了，  
AI这块差距越来越大  
”。  
  
十年安全苦旅，一番少年情怀。  
  
****  
**<全文完>**  
  
****  
<table><tbody><tr style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><td data-colwidth="557" width="557" valign="top" style="padding: 5px 10px;border: 1px solid rgb(221, 221, 221);margin: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;"><span style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><strong style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 楷体;"><span leaf="">恭喜你，又看完了一篇文章。从今天起，</span><strong style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span leaf="">和我一起洞察安全与AI本质</span></strong><span leaf="">！这里是锐安全，今天就到这里，咱们</span><span style="margin: 0px;padding: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: red;"><span leaf="">下次</span></span><span leaf="">再见！</span></span></strong></span></td></tr></tbody></table>  
  
  
点击文末【**阅读原文**  
】,看到一个完整的安全系统  
  
end  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6SUs3WHn8P9QVFXd4lu03am0PtsHHPDtib3xhEFpJJw1TAbtMv0hrjSVKKgWm72fdhsPL6RbEbHZGTsiaFTiaxTYQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cXxu8rO9aeEoLicH7cEMZmicpEDhJicEicARW2EAzCkz4ClBBjTq0PvkSrINBsGDtfoSUsUxWKy1lXj5C6gvSfJLBA/640?wx_fmt=png "")  
  
**如果你对本文有任何建议,**  
  
**欢迎联系我改进；**  
  
**如果本文对你有任何帮助，**  
  
**欢迎****分享****、点赞和在看**  
  
****  
  
         
  
  
****  
  
