#  【论文速读】| VADER：漏洞评估、检测、解释和修复的人工评估基准  
原创 知识分享者  安全极客   2025-06-10 10:08  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
原文标题：  
  
VADER:AHuman-EvaluatedBenchmarkforVulnerabilityAssessment,Detection,Explanation,andRemediation  
  
原文作者：  
  
EthanTS.Liu,AustinWang,SpencerMateega,CarlosGeorgescu,DannyTang  
  
作者单位：AfterQuery（研究人员分别来自UCBerkeley、宾夕法尼亚大学等）  
  
关键词：大语言模型、漏洞检测、漏洞修复、VADER基准、安全评估、人工审核、安全补丁、CWE分类  
  
原文链接：https://arxiv.org/abs/2505.19395v1  
  
开源代码：https://github.com/AfterQuery/vader  
  
  
**论文要点**  
  
  
论文简介：本文提出了一个名为VADER的全新基准体系，用于系统评估大语言模型（LLMs）在软件安全领域的表现，尤其聚焦在漏洞评估、检测、解释与修复四个关键环节。该基准共包含174个真实漏洞案例，涵盖15种编程语言，来源于GitHub等开源代码库，并由资深安全专家进行人工标注和复审。论文评测了六个主流LLM模型（如GPT-4.5、Claude3.7、Gemini2.5等）在这一基准下的表现，结果显示当前模型仅能中等程度地完成任务，最优秀模型的平均准确率也仅为54.7%。论文还发现，模型在漏洞修复质量与漏洞分类、测试计划制定之间存在高度相关性（Pearsonr>0.97），这说明模型在理解能力方面仍有较大提升空间。VADER的构建为研究界提供了一个可复现、可解释的标准平台，用于推动更具安全意识的大语言模型研究。  
  
研究目的：  
  
近年来，大语言模型在代码生成和辅助编程中显示出强大能力，被业界广泛应用于代码自动化处理。然而，当前的模型在处理跨语言、多文件、复杂上下文的真实漏洞场景下，依然面临巨大挑战。过去的漏洞检测数据集大多基于合成代码片段或单函数分析，未能涵盖完整的安全生命周期。本文旨在填补这一空白，提出一个具备真实漏洞案例、详细标注信息、人工审核机制与可复现评分系统的VADER基准，系统衡量LLM在完整软件安全处理流程中的表现，包括识别漏洞、解释其成因、提出补丁及测试验证其修复效果。通过这一基准，研究人员能更准确判断现有模型的实际能力与瓶颈所在，推动安全感知型大语言模型的进一步发展。  
  
  
**引言**  
  
  
近年来，大语言模型（LLMs）在自动代码生成和辅助软件开发中取得显著进展，然而其在安全领域的能力仍未充分验证。GitHubCopilot等工具已开始集成AI进行漏洞修复建议，OpenAI等也发布了面向安全分析的集成连接器。然而，漏洞检测与修复不仅需要识别问题代码，更需要准确分类漏洞类型、理解成因、提出合理补丁并构造测试计划以验证修复有效性。现有评估手段大多仅关注漏洞检测准确率，忽视了解释与修复质量的全流程能力评估。此外，绝大多数基准仅覆盖单语言、单文件的合成样本，远离真实生产环境中的复杂性。  
  
本文提出的VADER基准填补了上述空白。其数据来源全部为真实开源项目中的安全漏洞，涵盖Web前端、后端服务、系统编程等多类场景；每个案例均由安全专家编写完整说明、修复方案及验证测试；并通过双层审核机制确保数据质量。论文不仅提出了新颖的评分标准，还首次对主流LLM进行全面评估，发现当前模型在“解释+修复”能力上远未达到实际应用所需水平。此外，研究还指出漏洞分类能力与修复效果之间存在极强正相关性，提示未来模型应加强对漏洞本质的理解。  
  
  
**相关工作**  
  
  
过往数据集如JULIET、DEVIGN、BIG-VUL等虽为漏洞检测提供了基础训练样本，但其大多基于静态、合成示例，缺乏复杂语境与多文件结构。诸如SECURITYEVAL、REPOSVUL等后续工作虽拓展了真实代码范围，但仍以“是否存在漏洞”这一单一目标为主，未涉及解释、补丁生成或验证测试。此外，像CVE-BENCH、NYUCTF等则转向交互式环境评估模型的攻击或修复能力，但也未覆盖“解释为何存在漏洞”等关键安全能力。  
  
相比之下，VADER首次将评估范围扩展至完整安全处理链条，要求模型不仅识别漏洞，还需合理解释成因、撰写补丁、设计测试计划。这一设计显著提升了模型对安全问题的深度理解要求。  
  
  
**基准构建**  
  
  
VADER基准的构建过程极为严谨，模拟真实的安全审查流程，确保数据的准确性和高质量。整个数据集由174个真实软件漏洞案例组成，均从开源项目中精心挑选，涵盖了如Python、JavaScript、Go、C/C++等15种主流编程语言。VADER的数据生成采用“双重人工标注机制”：首先由一名资深安全专家提交漏洞案例，随后由另一名独立审查员进行验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SdfCGFDVFYdaFTakRFdwPM8iceZQfSTnHNRpdd0rCeW5Evyplql9xOLlsYyDDM3UKPOxcSgYV7pzA/640?wx_fmt=png&from=appmsg "")  
  
在案例提交阶段，专家需提供一份完整的漏洞报告，包括但不限于：具体的漏洞代码片段、详细的漏洞解释（含根本原因、利用方式与影响）、对应的CWE编号、建议修复补丁（goldenpatch）以及可验证修复有效性的测试计划。每个补丁要求尽可能简洁明了，只改动与漏洞直接相关的代码，避免冗余或破坏原有逻辑。  
  
审查阶段由拥有6年以上经验的安全工程师复核案例质量。他们从漏洞真实性、补丁有效性、解释完整性及测试计划的合理性等多个维度进行严格审核，只有全部符合标准的案例才会被纳入正式基准。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SdfCGFDVFYdaFTakRFdwPMrRtbqlF8HC4dxrqicSLdtLRTsbRLY49TAjUlBziaz0FqUSqg7gE2TWew/640?wx_fmt=png&from=appmsg "")  
  
这种双审流程不仅确保了每个漏洞样本的真实性与高质量，还保证了其在实际安全分析中具有充分的参考价值。此外，VADER还根据漏洞的严重程度进行打分，采用五级标准（非常低至致命），其中高危和致命级别漏洞占比超过60%，极大增强了基准对大语言模型安全处理能力的挑战性。通过该构建流程，VADER成为业界少有的，能系统覆盖“检测、解释、修复、验证”全流程的高可信度安全基准。  
  
  
**研究评估**  
  
  
为全面评估大语言模型在处理真实软件漏洞中的实际能力，VADER设计了一套严谨统一的评估体系。论文选择了当前业界最具代表性的六大主流LLM模型作为评测对象，分别为：OpenAI的o3、GPT-4.1与GPT-4.5，Google的Gemini2.5Pro，Anthropic的Claude3.7Sonnet，以及xAI的Grok3Beta。这些模型覆盖了不同厂商、不同架构与上下文处理能力，具备代表性和广泛性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SdfCGFDVFYdaFTakRFdwPMBlhoFibsnicAQV3oSM6DLjWtG6bTOyGPWBouprTOZQXNvLR3VpeiaQiaUg/640?wx_fmt=png&from=appmsg "")  
  
评估采用“一轮提示”（one-shotprompting）策略，每个模型在每个漏洞案例中只收到一次统一格式的输入，包括漏洞相关的代码文件和任务描述，要求其完成漏洞识别、CWE分类、原因解释、补丁编写及测试计划制定五项任务。为了确保测试公平性，所有模型接收到的提示完全一致，且不进行任何模型专属微调。  
  
模型输出由具备丰富经验的安全专家使用结构化评分标准进行双人盲评。评分体系共分三大维度：漏洞修复质量（占总分的50%）、漏洞解释准确性（20%）、以及CWE分类与测试方案（30%）。每个维度根据准确性、完整性、技术合理性进行细分评分，满分为10分。  
  
此外，为避免评分偏差，每个模型的输出结果都由两位评审独立打分，并计算平均得分。值得注意的是，在漏洞修复这一核心环节中，专家更看重的是补丁的简洁性、可编译性、是否真正消除漏洞以及是否引入新风险；而在解释维度中，模型需精准描述漏洞的根本成因、可被攻击的方式及其安全影响。  
  
通过这一严谨的评估流程，VADER不仅能量化对模型“写代码”的能力，还能深入洞察其是否真正理解漏洞原理、是否能提出合理修复方案、是否具备将安全问题“闭环解决”的综合能力。相比传统只考察分类或检测准确率的数据集，VADER评估体系更加全面、真实，能更贴近实际应用中对安全助手的期待。  
  
  
**研究结果**  
  
  
VADER基准的评测结果显示，当前主流大语言模型在真实漏洞处理任务中的整体表现仍属中等水平，远未达到“可生产部署”的理想状态。在全部174个真实漏洞案例中，得分最高的模型是OpenAI的o3，平均得分为5.47分（满分10分），约合54.7%的准确率。紧随其后的是Google的Gemini2.5Pro（53.6%）和OpenAI的GPT-4.5（49.2%），而Anthropic的Claude3.7、GPT-4.1以及xAI的Grok3Beta则处于中等偏下水平，最低者Grok仅为44%左右。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SdfCGFDVFYdaFTakRFdwPMwYLRF4h5BEaiaXknM3CZMmwLViapTtL4AL3tnNaIen96xLvThkvenRMw/640?wx_fmt=png&from=appmsg "")  
  
研究还揭示了一个关键趋势：模型在漏洞修复、解释、分类与测试等各项能力之间存在显著相关性。其中，漏洞修复质量与CWE分类及测试计划能力之间的皮尔逊相关系数高达0.97以上。这表明，模型若能准确识别漏洞类型与影响，通常也能更好地完成修复任务。  
  
整体而言，VADER测试强调了模型“理解-解释-修复-验证”全链条能力，而目前的模型在处理复杂、跨文件、真实漏洞时，仍面临严峻挑战，亟待突破。  
  
  
**论文结论**  
  
  
本文提出的VADER基准为衡量大语言模型在漏洞评估、检测、解释和修复四大能力上的表现提供了统一标准。通过人工标注、全流程设计与开放工具链，该基准不仅真实、可复现，还具高度挑战性。测试结果显示，目前主流模型在该任务上均仅达中等水准，仍无法满足生产级别应用的安全要求。未来工作可在模型理解力、跨文件推理能力与测试生成方面进一步优化，以提升其在真实漏洞修复中的实用性。VADER的开放发布也为学术与工业界提供了一个长期演进的评测平台，推动“安全感知型AI”走向落地。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8R7Rm0KL55HCcIiasO8JJ7IibXzYxx3losWVb2eddxdClACzWxWtQLwl0wkAl1ZLibcESVWvx5dCeibtQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QRqLMRicZIN6VJg0ue41W1HVSmDpDqkj86j5SNicNE3X5KkPgcdv1ZmxM7FXrFUdkBes8dpos7d27w/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
