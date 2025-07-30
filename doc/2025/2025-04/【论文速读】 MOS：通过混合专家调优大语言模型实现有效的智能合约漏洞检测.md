#  【论文速读】| MOS：通过混合专家调优大语言模型实现有效的智能合约漏洞检测   
原创 知识分享者  安全极客   2025-04-29 07:32  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
原文标题：MOS: Towards Effective Smart Contract Vulnerability Detection through Mixture-of-Experts Tuning of Large Language Models  
  
原文作者：Hang Yuan, Lei Yu, Zhirong Huang, Jingyuan Zhang, Junyi Lu, Shiqi Cheng, Li Yang, Fengjun Zhang, Jiajia Ma, Chun Zuo  
  
作者单位：暂无具体单位标注  
  
关键词：Smart Contract, Vulnerability Detection, Large Language Models, Mixture-of-Experts  
  
原文链接：https://arxiv.org/abs/2504.12234  
  
开源代码：暂无  
  
  
**论文要点**  
  
  
论文简介：智能合约漏洞给区块链系统带来了重大的安全风险，有可能导致严重的经济损失。现有的方法存在一些局限性：（1）基于程序分析的方法严重依赖预定义的模式，缺乏对新漏洞类型的灵活性和适应性；（2）基于深度学习的方法对其检测结果缺乏解释；（3）基于大语言模型的方法存在较高的误报率。  
  
为了应对这些挑战，研究者提出了 MOS，这是一个基于大语言模型的专家混合调优（MOE-Tuning）的智能合约漏洞检测框架。首先，研究者在大规模的智能合约数据集上进行持续预训练，为后续的专家混合调优过程提供领域增强的初始化。其次，为了给检测到的漏洞提供可靠的解释，研究者通过结合大语言模型生成和专家验证的多阶段流程构建了一个高质量的专家混合调优数据集。第三，研究者设计了一种漏洞感知路由机制，通过分析代码特征及其与专家的匹配程度来激活最相关的专家网络，从而解决了程序分析方法中预定义模式的局限性。最后，研究者将持续预训练后的大语言模型的前馈层扩展为多个并行的专家网络，每个网络专门处理特定的漏洞模式。  
  
研究者还采用了一个双目标损失函数：一个用于优化漏洞检测和解释性能，另一个用于通过计算专家负载分布的熵来确保不同漏洞类型合理地分配给相应的专家，从而提高模型在复杂漏洞场景下的性能。  
  
大量实验表明，MOS 显著优于现有的最先进方法，F1 分数平均提高了 6.32%，准确率平均提高了 4.80%。MOS 生成的漏洞解释也展现出了高质量，通过人工评估和大语言模型评估相结合的方式，在正确性、完整性和简洁性方面分别获得了 82.96%、85.21% 和 94.58% 的正面评价（在 4 分制中得分为 3 分和 4 分）。  
  
研究目的：本研究旨在解决传统漏洞检测工具在精度、覆盖面和可解释性上的瓶颈。作者基于LLaMA模型，通过持续预训练和专家网络转换，构建出一个能够精细识别漏洞类别、分析安全影响并提供人类可读解释的检测框架MOS。其最终目标是帮助开发者更早、更准确地发现智能合约中的安全问题，从而规避链上不可逆的经济损失。  
  
研究贡献：  
  
1. 研究者提出了 MOS，这是首个利用大语言模型的专家混合调优来进行智能合约漏洞检测的框架。研究者的方法将漏洞感知的专家路由与专门的专家网络相结合，在四种主要的漏洞类型检测上达到了当前最先进的性能水平，同时还能提供可靠的解释。  
  
2. 研究者开展了全面的实验，证明了 MOS 的有效性，与现有方法相比，其 F1 分数平均提高了 6.41%，准确率平均提高了 4.80%。通过人工评估和大语言模型评估相结合的方式，研究者验证了该模型生成准确、全面且简洁的漏洞解释的能力，并且在所有评估维度上都具有很强的评分者间信度（Kappa 值大于 0.4）。  
  
3. 为了推动相关领域的进一步研究，研究者公开了研究者的数据集以及 MOS 的源代码。  
  
  
**引言**  
  
  
随着区块链技术的普及，智能合约已成为自动化数字资产管理的关键组件。但其固有的“不可更改性”也带来了巨大的安全挑战。一旦漏洞被部署至链上，将无法修复，轻则造成资产损失，重则动摇整条链的信任根基。历史上最著名的“DAO攻击”事件，便因一个重入漏洞导致超过6000万美元的以太坊被非法转移。  
  
传统的程序分析方法虽在漏洞检测方面取得一定进展，但仍面临三大问题：依赖专家预定义规则、难以覆盖复杂漏洞、误报率高。而近年来兴起的深度学习方法，虽然在检测精度上有所提升，却在可解释性方面表现乏力，使得开发者难以定位和修复问题。  
  
本论文的出发点正是解决以上挑战，作者提出MOS框架，通过专家混合机制，使模型在不同类型的漏洞上具备更强的检测与解释能力。MOS采用LLaMA模型作为基础，通过持续预训练建立合约知识，然后通过专家网络结构进行漏洞类型细分，提升检测准确性和可解释性。在四类典型漏洞（重入、时间依赖、整数溢出、delegatecall）上的实验证明了其显著优势。  
  
  
**研究背景**  
  
  
随着区块链技术的迅猛发展，智能合约作为其核心应用之一，正广泛应用于金融、保险、供应链等多个关键领域。智能合约是一种自动执行的代码逻辑，一旦部署至链上，便具备不可更改性与自治性。尽管这种特性带来了操作透明、成本降低等诸多优势，却也埋下了安全隐患：一旦存在漏洞，将无法像传统软件一样通过更新补丁进行修复，极易造成无法挽回的资产损失。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SaKHJ2NJhmmgp4fHXLSLllT4ibJtJ8pRGYq2WHR2VWfwA3ryyicDr9jCMAKTdibQqWlUodEiatFuKUuQ/640?wx_fmt=png&from=appmsg "")  
  
历史上多起严重安全事件揭示了智能合约脆弱的一面。例如著名的DAO攻击，黑客通过“重入漏洞”非法获取超过5000万美元的以太币，震动整个区块链行业；Parity多签钱包事件中，因“delegatecall”使用不当，导致2.8亿美元资产永久冻结。这些事故无一不强调了在合约部署前发现并修复安全漏洞的重要性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SaKHJ2NJhmmgp4fHXLSLllMM9Kj8CTJwnZCtH3xgmy8znjKao2mDdfwAJGkGN7w2AW83OicmuibiawA/640?wx_fmt=png&from=appmsg "")  
  
然而，现有的检测手段仍难以满足实际需求。传统的程序分析工具多依赖规则匹配和符号执行，难以覆盖复杂和新型漏洞，且误报率和漏报率较高；而基于深度学习的方法虽然在检测能力上有所提升，却普遍缺乏对漏洞原因和定位的解释能力，无法有效协助开发者修复问题；大语言模型（LLM）虽然具备强大的语言理解能力，但在实际应用中仍存在误判多、泛化弱、解释模糊等问题。因此，亟需一种兼具准确性、泛化能力与可解释性的智能合约漏洞检测新范式。MOS框架正是在这样的背景下应运而生。  
  
  
**研究方法**  
  
  
本研究提出的MOS（Mixture-of-Experts for Smart contract vulnerabilities）方法，以大语言模型为基础，通过“专家混合机制”（Mixture-of-Experts, MoE）架构，实现对智能合约多类型漏洞的精准检测与解释。整体方法主要分为三个核心阶段：持续预训练、专家网络构建与微调（MOE-Tuning），以及漏洞感知路由机制设计。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SaKHJ2NJhmmgp4fHXLSLllVn3ZibzbMDXjpLLV2PmTCVlnicf59wmL1hcVz2s3pB8rb9EoKTuzD3cA/640?wx_fmt=png&from=appmsg "")  
  
首先，在“持续预训练”阶段，研究团队以LLaMA-3.2-3B为基础模型，在超过62万条合约数据和跨学科文本（如数学、英语、代码等）上进行再训练，从而赋予模型更强的合约语义理解能力，为后续专家结构提供坚实基础。  
  
其次，在模型结构上，作者设计了专门的“专家网络层”，将原始模型的前馈网络（FFN）扩展为多个并行的专家子网，每个专家专注于检测一种特定漏洞类型，如重入攻击、时间依赖、整数溢出和delegatecall漏洞。这些专家网络结构相同、参数独立，通过训练获得专属知识。  
  
为了实现智能路由，MOS引入“漏洞感知路由器”，该组件根据输入代码特征（如是否存在外部调用、算术操作、时间戳依赖等）动态计算与每个专家的匹配度，选取最合适的专家组合进行推理。训练过程中，MOS采用双重目标函数：一方面优化漏洞检测与解释效果，另一方面通过熵正则约束专家分布，防止模型过度依赖少数专家，从而提升多类型漏洞场景下的整体表现与稳定性。  
  
  
**研究评估**  
  
  
为了全面验证MOS框架在智能合约漏洞检测任务中的有效性，研究团队设计并实施了多维度的实验评估。评估过程主要聚焦两个关键能力：漏洞检测性能与解释质量。  
  
在检测性能方面，MOS在四大主流漏洞类型——重入攻击、时间依赖、整数溢出/下溢、delegatecall调用——上均显著超越现有主流检测方法。实验采用多个权威数据集（包括SmartBugs和Qian等研究者整理的数据）作为测试基准，覆盖数百个经过人工标注的合约样本。评估指标包括准确率（Accuracy）、精确率（Precision）、召回率（Recall）与F1分数。结果显示，MOS在所有四类漏洞上F1得分分别提升了10.02%、1.92%、3.60%与9.75%；准确率则平均提升4.8%。这些数据充分证明了MOS在复杂漏洞场景中的识别能力与稳定性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SaKHJ2NJhmmgp4fHXLSLllaSL9zPwSmmNk8J341JbjL6DHwibQCFcTq7OArjSeQtC1jsmS7ibfTDYw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SaKHJ2NJhmmgp4fHXLSLllOoZaPWu7Ts3B3xdCE5582svM5ESqSPdvfHW65C0I3hhjKawcwZKmfQ/640?wx_fmt=png&from=appmsg "")  
  
在解释能力方面，MOS同样表现出色。研究团队设计了三维度评价标准——正确性（Correctness）、完整性（Completeness）、简洁性（Conciseness），并采用人工专家评审与大语言模型（LLaMA-3.1-70B）评估结合的方式进行打分。MOS所生成的漏洞解释在三项指标上的正向评分比例分别达到82.96%、85.21%和94.58%。此外，通过Cohen’s Kappa系数计算评审一致性，结果表明模型输出具备高度稳定性与可信度。  
  
不仅如此，研究还分析了失败案例与专家激活频率，发现MOS模型具备良好的专家分工特性，浅层捕捉通用语义，深层专注于特定漏洞，从结构上实现了更强的泛化能力和可解释性。  
  
  
**研究结论**  
  
  
本文提出的MOS系统，成功将专家混合机制引入到大语言模型中，显著提升了智能合约漏洞检测的精度与可解释性。实验表明，MOS在多项指标上超越现有方法，且能生成高质量的漏洞解释。此外，MOS的专家网络在检测不同类型漏洞时表现出清晰的分工与合作，证明了其模型架构的创新性和实用性。  
  
未来研究可在提升专家路由鲁棒性、扩展支持漏洞类型、降低推理资源消耗等方向上进一步优化MOS系统，推动其在实际区块链安全检测中的落地应用。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8R7Rm0KL55HCcIiasO8JJ7IibXzYxx3losWVb2eddxdClACzWxWtQLwl0wkAl1ZLibcESVWvx5dCeibtQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&retryload=1&tp=webp "")  
  
