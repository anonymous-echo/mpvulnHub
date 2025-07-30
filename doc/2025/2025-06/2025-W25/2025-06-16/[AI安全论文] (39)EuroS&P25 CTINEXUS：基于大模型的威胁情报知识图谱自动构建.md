> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501830&idx=1&sn=f599d82d75d597ab4a2deaccd84da2ef

#  [AI安全论文] (39)EuroS&P25 CTINEXUS：基于大模型的威胁情报知识图谱自动构建  
原创 钟睿杰  娜璋AI安全之家   2025-06-16 08:59  
  
> 2024年4月28日是Eastmount的安全星球 —— 『网络攻防和AI安全之家』正式创建和运营的日子，并且已坚持5个月每周7更。该星球目前主营业务为 安全零基础答疑、安全技术分享、AI安全技术分享、AI安全论文交流、威胁情报每日推送、网络攻防技术总结、系统安全技术实战、面试求职、安全考研考博、简历修改及润色、学术交流及答疑、人脉触达、认知提升等。下面是星球的新人券，欢迎新老博友和朋友加入，一起分享更多安全知识，比较良心的星球，非常适合初学者和换安全专业的读者学习。  
> ”  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNNFeiah4SQp0vALsK4dS3mGZwKaOS8IaXoRkfIKKeiauEvZX3qHFhib6YY9nlibHGYPJicLrmwRMOD5PA/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
忙碌的五月终于过去，忙到来不及分享，六月开启，继续更新博客，感谢大家的支持，久等了！  
  
《娜璋带你读论文》系列旨在督促自己阅读优秀论文和学术讲座，希望您喜欢。由于作者的英文水平和学术能力不高，需要不断提升，所以还请大家批评指正，非常欢迎大家给我留言评论，学术路上期待与您前行，加油。  
  
该文是贵大0624团队论文学习笔记，分享者钟睿杰同学，未来我们每周至少分享一篇论文笔记。前一篇博客总结了基于大模型的威胁情报分析与知识图谱构建论文。这篇文章将带来EuroS&P’25弗吉尼亚理工大学和加州大学伯克利分校——基于大模型的威胁情报知识图谱自动构建系统（CTINEXUS），本文的主要贡献是实现了在数据受限条件下的高效CTI知识抽取与高质量网络安全知识图谱，能仅通过极少的标注示例即可适应多种本体体系。此外，由于我们还在不断成长和学习中，写得不好的地方还请海涵，希望这篇文章对您有所帮助，这些大佬真值得我们学习。fighting！  
### 文章目录  
- 一、摘要   
  
- 二、研究背景与动机  
  
- 三、本文模型   
  
- 1.Overview   
  
- 2.Cybersecurity Triplet Extraction   
  
- 3.Hierarchical Entity Alignment   
  
- 4.Long-Distance Relation Prediction  
   
  
- 四、实验评估   
  
- 1.与主流方法对比   
  
- 2.各阶段优化分析  
   
  
- 五、结论与展望  
   
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWuOKRyjhrMNywic6p71jO16uXiaeMWmCaXhtkVR3icy5a98mxnC9I0sG6A/640?wx_fmt=png&from=appmsg "")  

```
原文作者：Yutong Cheng, Osama Bajaber, Saimon Amanuel Tsegai, 
Dawn Song, Peng Gao（Virginia Tech，UC Berkeley） 
原文标题：CTINEXUS: Automatic Cyber Threat Intelligence Knowledge 
Graph Construction Using Large Language Models 
原文链接：https://arxiv.org/abs/2410.21060 
发表会议：IEEE EuroS&P 2025
博客作者：贵大0624团队 钟睿杰
开源代码：https://github.com/peng-gao-lab/CTINexus
```

  
  
**一.摘要**  
  
网络威胁情报（Cyber Threat Intelligence, CTI）报告中的文本描述，如安全文章与新闻报道，是网络威胁知识的重要来源，对于组织掌握快速演化的威胁态势至关重要。然而，当前的CTI知识抽取方法在灵活性与通用性方面存在明显不足，常导致知识抽取结果不准确或不完整。**语法解析方法依赖固定规则与词典，难以适应新的威胁类型和本体结构；而模型微调方法则依赖大量人工标注数据，限制了其在低资源场景下的可扩展性。**  
  
为弥合这一差距，**本文提出了一种新型框架CTINexus，该框架基于大型语言模型（LLMs）的优化上下文学习（In-Context Learning, ICL）机制，实现在数据受限条件下的高效CTI知识抽取与高质量网络安全知识图谱（Cybersecurity Knowledge Graph, CSKG）构建。**  
 与传统方法不同，CTINexus无需大量训练数据或复杂的参数调优，仅通过极少的标注示例即可适应多种本体体系。这一能力的实现依赖以下关键技术：  
- （1）自动化构建提示词的策略，结合最优示例检索，支持多类别安全实体与关系的高效抽取；  
  
- （2）分层实体对齐方法，对抽取得到的知识进行规范化与去冗余处理；  
  
- （3）远距离关系预测机制，用于补全知识图谱中的缺失链接。  
  
在150份来自10个平台的真实CTI报告上开展的大规模实证研究显示，CTINexus在构建准确、完整的CSKG方面显著优于现有方法，充分展示了其作为一种高效、可扩展的动态威胁分析解决方案的潜力。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWOKqLI3Pjo73kVxDpibWpUtH5Meiaovwt8puc1az99ET0fqzQ3N6KmetA/640?wx_fmt=png&from=appmsg "")  
#   
  
**二、研究背景与动机**  
# 随着网络攻击的日益复杂和持续演化，高质量的网络威胁情报（Cyber Threat Intelligence, CTI）成为构建防御能力的关键。CTI 报告（如APT分析、威胁通报）中通常蕴含着丰富的攻击者、工具、目标、攻击方式等实体信息，但大多以非结构化自然语言形式存在。  
  
当前存在几种方法能自动提取来自网络威胁情报（CTI）的安全知识并构建网络安全知识图谱（CSKG）。基于语法解析的方法依赖于固定的依赖规则和手工制作的词典来解析句子的语法结构，并提取关键的主谓宾三元组。基于微调的方法利用预训练的变换器，并在标记的CTI数据集上对其进行微调，以识别语义角色并提取实体和关系。  
  
然而，这些方法存在几个主要缺陷，尤其是在面对不断变化的威胁环境时缺陷如下：  
- **缺乏灵活性和普遍适用性**  
这些方法中的许多都是针对特定的网络安全本体量身定制的，关注于固定的实体和关系类型。它们很难推广到新的本体和新兴威胁及术语。固定规则在适应新模式上灵活性有限，并且需要手动创建和维护。  
  
- **过度依赖数据标注**  
模型微调需要大量标注过的网络威胁情报（CTI）语料库数据。这些数据在安全领域中稀缺，特别是对于缺乏注释的新威胁，难以适应新兴威胁和本体结构变化。  
  
- **信息不准确和不完整**  
由于安全背景的特殊性和缺乏深入分析，这些方法通常生成低质量的知识图谱（CSKG），这些图谱是不完整、不准确和断开的，难以支撑高质量威胁建模和响应。  
  
在当前APT威胁情报结构化研究中，已有方法如Extractor、TTPDrill、LADDER等在信息提取方面取得了一定进展。然而，正如图中所示，这些方法在处理同一份CTI报告时仍存在以下显著问题：  
- **实体对齐缺失**  
例如攻击组织、恶意软件、目标实体等在不同句子中未能建立明确的跨句对齐或归一化链接，导致图谱构建碎片化。  
  
- **关系抽取不完整**  
许多关键的行为链关系未被识别或遗漏，严重影响了对攻击链的理解与推理。如实体边界错误（如"registry values and ransom note"被合并）。  
  
- **上下文理解薄弱**  
多跳关系（间接行为因果链）与同义事件的抽象归并能力不足，限制了攻击模式的完整还原， 如子图间缺乏关联（如"威胁组织"与"利用的漏洞"无显式关系）。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWFWbEMBJI6KWXOc9f7IUSMBxZbBR3S1ghRGibn2aoDiclf7zmpK9yhIGA/640?wx_fmt=png&from=appmsg "")  
  
为突破上述瓶颈，本文旨在构建一个数据高效、可泛化、无需微调的新框架，借助大语言模型（Large Language Models, LLMs）的上下文学习能力（In-Context Learning, ICL），自动从CTI文本中抽取实体与关系，构建结构化的CSKG，从而支持安全分析与自动防御。  
  
  
**三、本文模型**  
# 1.Overview  
  
本文提出CTINexus框架，基于LLM上下文学习（ICL）实现数据高效的CSKG构建，主要创新如下：  
- **ICL优化的信息抽取机制**  
  
利用kNN检索选取与目标CTI报告相似的示例构造提示（prompt），结合本体知识，指导LLM抽取实体-关系三元组，避免冗长对话式提问，显著减少token消耗。  
  
- **分层实体对齐机制（图4）**  
  
粗粒度对齐通过ICL对实体进行类型分类（如Threat Actor、Malware等）；精细化对齐基于向量嵌入合并语义相似的实体，并设计IOC保护机制避免误合并（如IP地址与恶意软件名混淆）。  
  
- **远程实体关系推理（图5）**  
  
基于子图中的度中心性选出核心实体，通过ICL推理这些中心节点与主题节点（topic entity）之间的隐式关系，连接原本离散的子图，提升CSKG的连通性。  
  
图2展示了CTINEXUS的整体流程，展示从CTI报告输入到三元组抽取、实体融合、远程推理的全流程。共分为三大阶段：  
- **Phase 1: 安全三元组抽取（Cybersecurity Triplet Extraction）**  
  
输入为一篇CTI报告；通过kNN检索相似示例报告；构造统一ICL提示（instruction + examples + query），由LLM直接输出所有相关三元组；图3展示了与传统多轮提问相比，CTINEXUS的“单轮抽取”在效率与准确性上明显优越。  
  
- **Phase 2: 分层实体对齐（Hierarchical Entity Alignment）**  
  
粗粒度使用ICL模板对triplet中主客体进行实体类型分类（如图4所示）；细粒度使用text-embedding-3-large模型嵌入同类实体，合并相似度高于阈值（0.6）的实体。  
  
- **Phase 3: 长距离关系推理（Long-Distance Relation Prediction）**  
  
图5中采用图结构分析选出各子图的中心实体；使用ICL模板构造问题推理这些中心实体与topic entity之间的关系，补全跨段落或跨句式的隐式链接。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWS7Wku1xQ0LNIm3m5bicESR9g7fTmpcOdtwf2I2ibJxUViacTz2sKkM4Rg/640?wx_fmt=png&from=appmsg "")  
  
该框架整合了 LLM 推理能力、上下文对齐机制与图结构分析手段，形成了端到端、高鲁棒性的网络威胁情报抽取与增强方法。下文将对各阶段进行更细致的说明。  
  
  
## 2.Cybersecurity Triplet Extraction  
  
图3对比展示了 CTINexus 所提出的基于上下文学习（ICL）的威胁情报抽取方法（左）与传统多轮问答式抽取方法（右）的核心差异。  
- **左侧CTINexus**  
将抽取任务设定为结构化三元组识别，模型以“网络安全分析员”的角色接收任务指令，并依据安全本体（如 Threat Actor、Action、Vulnerability 等）进行类型约束。通过 KNN 检索获得最相关的 K 个示例，构造成 Few-shot Prompt，其中包含示例、标签与待分析文本。模型一次性完成推理并输出 JSON 格式结果，实现高效的一体化信息抽取。  
  
- **右侧对比方法**  
传统多轮问答式方案将任务拆分为多个子任务：攻击目标提取、攻击者提取、实体关系识别等，每个子任务独立设计 Prompt 并分别调用模型。该方法需多轮交互，抽取过程碎片化，不仅效率低下，还可能导致结果间语义不一致。  
  
有图可知，CTINEXUS在“Instruction + Examples + Query”结构中的信息浓缩能力，避免冗余问答与格式误差。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJW33N45AzQqJUgkG1Q4XqHNYEnML8PXxDnuk9wh836efVsmLSfV3lnNA/640?wx_fmt=png&from=appmsg "")  
## 3.Hierarchical Entity Alignment  
  
图4为实体对齐流程图，细化了从类型标注、聚类到安全过滤的步骤，IOC保护机制有效避免误合并关键实体（如CVE ID、IP地址等）。  
  
在对齐部分，我们首先会使用LLM基于左侧的提示词和本体设置对每个实体进行一个粗粒度的分类，映射到某一个类别之中，在对每一个类别里面的实体进行细粒度的分类，使用分层算法进行对齐。  
- **粗粒度实体分类**  
为了提供结构化的归类基础，系统预定义了一个涵盖 20 类核心安全要素的本体（CSKG Ontology），例如 Threat Actor、Vulnerability、Exploit Target、File 等。对于每一个三元组中的实体，我们通过 Few-shot Prompt 的方式，引导大模型对其 subject 与 object 进行初步分类，从而将实体统一映射到相应的类别空间中，完成粗粒度的语义聚类。  
  
- **细粒度实体合并**  
在粗分类的每一个实体类别簇内，仍然可能存在语义一致但名称不同的冗余实体。为此，我们进一步使用大模型对实体进行向量编码，并在潜在语义空间中进行相似度比较。系统依据设定阈值（如 Sim > Thresh）自动判断是否合并，从而完成同类实体的细粒度对齐与归一化。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWF8V27v7wqCdgY5zXDchNxAg0TC261t4QAQ2ISASBP9t2U9XZibIktdg/640?wx_fmt=png&from=appmsg "")  
## 4.Long-Distance Relation Prediction  
  
图5展示了CTINEXUS框架中第三阶段“长距离关系预测（Long-Distance Relation Prediction）”的完整流程设计，解决的是CTI文本中不同段落或句子中提及的实体之间缺乏显式关联的问题，确保最终构建的CSKG具有更好的连通性和完整性。  
- **子图遍历与中心实体识别**  
  
在初步抽取的知识图谱中，不同的三元组往往构成多个孤立的子图。为此，我们首先采用 DFS 算法对每个子图进行遍历，并在每个子图中寻找出度最高的实体，作为该子图的中心实体（蓝色节点）。  
  
- **主题实体确定**  
  
在所有子图的中心实体中，我们进一步比较其出度，选取出度最大的一个作为整篇报告的主题实体（黄色节点），以此作为长距离关系补全的语义核心。  
  
- **隐含关系预测与补全**  
  
最后，系统基于构造好的提示词模板，逐一推理主题实体与其他中心实体之间是否存在潜在的语义关系，从而补全原始图谱中未被显式提及的远程三元组，提升整体图谱的连通性与推理深度。  
  
具体而言，其关键步骤包括：  
- **Phase 1：中心实体识别（Central Entity Identification）**  
  
对CSKG执行深度优先遍历，将其划分为多个连通子图。使用度中心性（Degree Centrality）指标，选出每个子图中边最多的实体作为“中心实体（Central Node）。在所有中心实体中，再选出度数最高者作为主题实体（Topic Node），即本报告最核心的威胁对象。  
  
- **Phase 2：基于ICL的关系推理（ICL-Enhanced Relation Inference）**  
  
推断中心节点与主题节点之间可能存在但在原文本中未明确指出的“隐式关系”。构建一个ICL提示模板（prompt template），包含上下文、问题和示例。由大语言模型（如GPT-4）根据上述提示，生成预测三元组（predicted_triplet），完成关系推理。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWSUOVdXKPkCnQM3K2XX3fnLibdkdjSq5CeTYQH2LjdPZiary5UJyNXE2w/640?wx_fmt=png&from=appmsg "")  
#   
  
**四、实验评估**  
  
提问式实验非常值得大家学习。  
- 5.2. RQ1: How does CTINEXUS compare against existing CTI knowledge extraction methods?  
  
- 5.3. RQ2: How do different settings affect the cybersecurity triplet extraction?  
  
- 5.4. RQ3: How do different settings affect the entity alignment and relation prediction?  
  
- 5.5. RQ4: How well does CTINEXUS perform in end-to-end CSKG construction?  
  
- 5.6. RQ5: How well does CTINEXUS adapt to different CSKG ontologies?  
  
- 5.7. RQ6: What is the efficiency of CTINEXUS?  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWo7ia5vJtYSLXL3tzC41opUPzF1m3prX4tHlyWtzLylMySbiaiaOialuWKA/640?wx_fmt=png&from=appmsg "")  
## 1.与主流方法对比  
- 三元组抽取性能：CTINEXUS F1-score为87.65%，远超EXTRACTOR（62.29%）；  
  
- 实体识别性能：CTINEXUS F1-score为90.13%，领先LADDER（71.13%）；  
  
- 长距离关系推理：使用GPT-4模型下可达F1-score 90.99%，远高于GPT-3.5的76.87%。  
  
表1展示了CTINEXUS与EXTRACTOR在网络安全三元组抽取任务中的性能对比。CTINEXUS在F1值（87.65）、精确率（93.69）和召回率（82.34）上均显著优于EXTRACTOR，表明其在准确性与信息覆盖方面具有更强的综合抽取能力。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWiaNPn7h7SQvXsZv7fsQTvZjfshW1fxJg0zYIDBJeZQ6NAlxfG38TOdQ/640?wx_fmt=png&from=appmsg "")  
  
表2展示了CTINEXUS与LADDER在网络安全实体抽取任务中的性能对比。CTINEXUS在F1值（90.13）、精确率（92.00）和召回率（88.35）上均大幅领先于LADDER，验证了其在实体识别任务中的精度与全面性显著提升  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWCrX4n2FHbH1J2EFL9MU0wEnVws4x7EkjMLYvUJaWI7l3CjDoib8BtZQ/640?wx_fmt=png&from=appmsg "")  
  
表3展示了CTINEXUS在不同示例数量下的抽取效果。结果显示，使用2个示例时F1最高（87.65），Precision 和 Recall 也较为平衡，且输入长度适中，体现出最优的性能与效率折中点。随着示例数增加，性能略有波动，但输入长度显著增长。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWtJqcYyS2rUnSwW5WoQuNJKA65hWzdg3VH9qNSQnxMGBqYWWOA2RgRw/640?wx_fmt=png&from=appmsg "")  
## 2.各阶段优化分析  
- 示例数量从1增至2显著提升准确性，进一步增加收益边际递减；  
  
- kNN-ascend排序策略优于random与descending，验证“示例靠近查询越有效”；  
  
- text-embedding-3-large在实体融合中F1达99.8%，优于SecureBERT等安全专用模型。  
  
表4显示了示例排列方式对CTINEXUS抽取性能的影响。结果表明，当示例按kNN相似度升序排列（kNN-ascend）时，模型表现最佳（F1为87.65），优于降序和随机排列，说明示例排序对推理效果有显著影响。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWnr2pZhwmGsSNhepibLVnIb6SZIiaAQWabyawEryEEUDBoF1FQp8Uicp0Q/640?wx_fmt=png&from=appmsg "")  
  
表5展示了不同基础模型对CTINEXUS网络安全三元组抽取性能的影响。结果表明，GPT-4在F1-Score、Precision和Recall三项指标上均表现最佳，显著优于GPT-3.5、Qwen2.5-72B和Llama3-70B，验证了其在复杂信息抽取任务中的强大推理能力。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWybibvZNh6t0aJu9XNYn45UP7K51k71JGgdSd5ma6RrSTiaXAo1BibmnBQ/640?wx_fmt=png&from=appmsg "")  
  
表9展示了在长距离关系预测任务中，不同模型及其示例数量配置对性能的影响。随着示例数量从0-shot增加至3-shot，GPT-3.5的F1-Score由65.95提升至最高76.87，再略微回落至74.83。相比之下，GPT-4在所有配置下均显著优于GPT-3.5，其中2-shot配置达到最高F1-Score为90.99，说明GPT-4在结合少量示例后能显著增强关系推理能力，具备更强的上下文学习与泛化能力。  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDROLFKfA8uQWRRrC7UcbyPJWibjQfKFssEyZuvzyQTfmNGeBgIT1PNBNiaicjNkzF7qiaozQcVm5JkUriaQ/640?wx_fmt=png&from=appmsg "")  
#   
  
**五、结论与展望**  
  
CTINEXUS展示了LLM+ICL在CTI知识抽取与CSKG构建中的显著优势，具备高准确率、高适应性、低数据依赖；对本体切换（如MALOnt到STIX）的出色兼容性，支持实时威胁图谱构建（如STIX格式输出），赋能入侵检测系统（如AlienVault OTX集成）；高计算效率。  
  
未来工作将探索：  
- 降低LLM幻觉影响  
  
- 图谱增强生成（KG-augmented Generation）  
  
- 安全可视化分析与问答系统集成  
  
- 使CSKG成为安全LLM的动态记忆与防御基础设施  
  
> 『网络攻防和AI安全之家』目前收到了很多博友、朋友和老师的支持和点赞，并且保持每周七次更新，尤其是一些看了我文章多年的老粉，购买来感谢，真的很感动，类目。未来，我将分享更多高质量文章，更多安全干货，真心帮助到大家。虽然起步晚，但贵在坚持，像十多年如一日的博客分享那样，脚踏实地，只争朝夕。继续加油，再次感谢！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNNFeiah4SQp0vALsK4dS3mGZwKaOS8IaXoRkfIKKeiauEvZX3qHFhib6YY9nlibHGYPJicLrmwRMOD5PA/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
(By:Eastmount 2025-06-16 周一夜于贵阳)  
  
**前文推荐：**  
- [[AI安全论文] 01.人工智能真的安全吗？浙大团队分享AI对抗样本技术](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247488844&idx=1&sn=5b6ee2f94c1d1af00879291c5d09a8b7&chksm=cfcca581f8bb2c97969f13181f75efba8425d106091e19bdca0d691917e6a2f2cc287d674b17&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 02.清华张超老师 GreyOne和Fuzzing漏洞挖掘各阶段进展总结](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247489681&idx=1&sn=ab4fae963c8038b251544e2b8c85dcf7&chksm=cfcca85cf8bb214a566c782b2036fe9fa13a81329da5305243357bc2ba2c5e5950a76679738e&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 03.什么是生成对抗网络？GAN的前世今生（Goodfellow）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247489893&idx=1&sn=d410e546e26970546ae153f0d13c1b00&chksm=cfcca9a8f8bb20beead7c0ec3cca3dd48bb3e4f11095fabf1993c63d37c1fd99af81f9b19ba7&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 04.NLP知识总结及NLP论文撰写之道——Pvop老师](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247490103&idx=1&sn=aee647efa6f6b69f4a87e282309a7fa9&chksm=cfccaafaf8bb23ec67b9485c22b2cfd889ca6d6e452d4afe20e78ab0371586601192fc96cf3b&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 05.RAID-Cyber Threat Intelligence Modeling Based on GCN](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247490941&idx=1&sn=30cf491cf7455bbd075f8285d292a9d8&chksm=cfccadb0f8bb24a6c4e87c5c95aecda92578ee634f2b8642bece665efde54417655ed79936c7&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 06.NDSS2020 UNICORN: Runtime Provenance-Based Detector for Advanced Persistent Threats](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247492967&idx=1&sn=60f14977758cc7d1e8504446422e5ec0&chksm=cfcf55aaf8b8dcbc86935b76e7f36961202174ecba1df597fee9d44428c607e80d41add1b2f9&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 07.S&P19 HOLMES：基于可疑信息流相关性的实时APT检测](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247492995&idx=1&sn=fa6733f5944fea0658184b9faa958a47&chksm=cfcf554ef8b8dc585ad504f62f3a17fb5d370ace4cce6919b0e4d9bdc1d5eb3dbaf18eba0a29&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 08.基于溯源图的APT攻击检测安全顶会论文总结](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247493942&idx=1&sn=58b1859718ad479dbb47d2bb6c8d7553&chksm=cfcf59fbf8b8d0ed8ac666ebfd24c403b9a9c468d5496b06769857848e4302def910b66fea40&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 09.ACE算法和暗通道先验图像去雾算法详解（Rizzi | 何恺明老师）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247494148&idx=1&sn=80407004e2b4be1d3a690b4c7f6e3b1e&chksm=cfcf5ac9f8b8d3df84538a13a4d98a7db7ddce20b6490e653671114269e8792906ad301edccf&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 10.英文论文引言introduction如何撰写及精句摘抄——以入侵检测系统(IDS)为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247494382&idx=1&sn=f86332f17e9994bbc7db677407a42032&chksm=cfcf5a23f8b8d3356f8f5f3b1cc41b2b8dee0ad03fbc2f54c0ecd3df96bd1d9d064b6bfb5d78&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 11.英文论文模型设计（Model Design）如何撰写及精句摘抄——以IDS为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247494496&idx=1&sn=b25f41b4fa475385a941237d47263c69&chksm=cfcf5badf8b8d2bbd4eee61587ae53c9d0f43214ba11368e2a7f8fcbb6803878361317916281&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 12.英文论文实验评估（Evaluation）如何撰写及精句摘抄(上)——以IDS为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247494542&idx=1&sn=04ded0c044e6503d74a1ae7d09e71227&chksm=cfcf5b43f8b8d255a5c60f7f340be1adc7793c8c7f6924033be376fd4d93180c855f0d5a52e6&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 13.英文SCI论文审稿意见及应对策略学习笔记总结](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495333&idx=1&sn=5a6940158af6f1f3b0813252f88f25df&chksm=cfcf5e68f8b8d77e9ad34551a7b8027376ec4480189778a2601e14655970a9f8e4fb37a6857a&scene=21#wechat_redirect)  
  
  
- [AI安全论文] 14.S&P2019-Neural Cleanse 神经网络中的后门攻击识别与缓解  
  
- [[AI安全论文] 15.Powershell恶意代码检测论文总结及抽象语法树（AST）提取](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495541&idx=1&sn=3855fc3b725f729458a5b79b956c934a&chksm=cfcf5fb8f8b8d6ae5f0bed62b49fb9ca37089b800e2ec081fb922c3f21955b4448af6a291610&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 16.CCS2019 针对PowerShell脚本的轻量级去混淆和语义感知攻击检测（经典）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495603&idx=1&sn=06f09373629c44a102e5d50292b50149&chksm=cfcf5f7ef8b8d668575a2c3c85f5190f3cc6737905bcd0d45c6f7efd19c77afb350a61bf2f9a&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 17.英文论文Design和Overview撰写及精句摘抄——以系统AI安全顶会为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495641&idx=1&sn=acb05997e38224a8a5773b9ad432b7ed&chksm=cfcf5f14f8b8d602bff70b516540af63def69e757c6cf0bf1c8673db499bcc0a96d03b5b3c82&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 18.英文论文Evaluation（实验数据集、指标和环境）撰写及精句摘抄——以系统AI安全顶会为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495724&idx=1&sn=9a98ca69797cb3603906b607d103aba9&chksm=cfcf40e1f8b8c9f752b99d5b6e6d24caf728843fdbfa08adac2eafc15494094f6054f1bdfa0d&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 19.USENIXSec21 DeepReflect：通过二进制重构发现恶意功能（经典）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247495981&idx=1&sn=fa34f5211e67a7d6c144019424657d22&chksm=cfcf41e0f8b8c8f6e91705e142147a6803ca1af45aa8173727e7858788b1473da5b00db25d7b&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 20.RAID19 基于Android移动设备的互联网流量中的位置数据泄漏分析（译文）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247496028&idx=1&sn=3496f17477927896c326e210995d5cd7&chksm=cfcf4191f8b8c887f6c7e4c879f375b2d1919cdb9ad924f6f4dd5bdbc9152dab24766d32a16c&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 21.S&P21 Survivalism经典离地攻击（Living-Off-The-Land）恶意软件系统分析](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247496069&idx=1&sn=f5aecaae5494b900b29f12078a2d632e&chksm=cfcf4148f8b8c85ee56fbab09252bb4dc90f936cfb6decaa860b5e91457c9838cfb35179041a&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 22.图神经网络及认知推理总结和普及-清华唐杰老师](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247496272&idx=1&sn=7eb79e3be42df3c8f002711a7bf1d410&chksm=cfcf429df8b8cb8b557e22567f6054b2450b053ea0314d5c9f461d6c7f64b0d27c2440844167&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 23.恶意代码作者溯源(去匿名化)经典论文阅读：二进制和源代码对比](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247496613&idx=1&sn=3dc22c85334a14c5fe1e138d95a494a0&chksm=cfcf4368f8b8ca7e5933ca3ad0096f4c21a48def945f0939a6781bf6481d642381e2ca47c173&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 24.向量表征：从Word2vec和Doc2vec到Deepwalk和Graph2vec，再到Asm2vec和Log2vec(一)](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247497037&idx=1&sn=cffdc902c0d53d48410836533ec641ef&chksm=cfcf4580f8b8cc9636b7fa19e7d583cb55cb3f9a7710d0d4723efff6de6e596e9a4841c7144d&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 25.向量表征经典之DeepWalk：从W2V到DeepWalk，再到Asm2vec和Log2vec (二)](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247497347&idx=1&sn=728715d641fe0980d56aceaa08d8552a&chksm=cfcf464ef8b8cf58d616e85b5e235648a8bfcb1680b94801024a114a04899cfc363410e61f92&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 26.基于Excel可视化分析的论文实验图表绘制总结——以电影市场为例](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247497650&idx=1&sn=7623a54a75bfc7cfb5587a3ef0adbcb2&chksm=cfcf477ff8b8ce69e1f516e08c302db26dd8b5a6148fc6b44c370d1947a943a3224951f28d5b&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 27.AAAI20 Order Matters: 基于图神经网络的二进制代码相似性检测（腾讯科恩实验室）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247498229&idx=1&sn=b2a40a551231fe4e307024d5518f8214&chksm=cfcf4938f8b8c02e1f7f07b766854120528a11b7e8312ca635a615d62c2ea4e5819b547e0029&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 28.李沐老师视频学习——1.研究的艺术·跟读者建立联系](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247498297&idx=1&sn=e3ff421c33a307f248b2d3f4fc7846cc&chksm=cfcf4af4f8b8c3e26c88f3bc25a572aab2450e76762be1d40e0c7cc77180e6f3a5b4e2d99613&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 29.李沐老师视频学习——2.研究的艺术·找问题和明白问题的重要性](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247498326&idx=1&sn=5f59698a717652e9192f3429b7c6269a&chksm=cfcf4a9bf8b8c38df716ffc5390d9076bd6043cd278c02a537ef7c24826309f92e6cb17a26cd&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 30.李沐老师视频学习——3.研究的艺术·讲好故事和论点](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247498416&idx=1&sn=d74dce08987bb531157fca1aed9cae22&chksm=cfcf4a7df8b8c36b6e8d30d8aa15e1917e14e12f18d7918fa7ece5d9196d1112c6568b9088ed&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] 31.李沐老师视频学习——4.研究的艺术·理由、论据和担保](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247498463&idx=1&sn=3d78c95e12c00a9176acbc9ad28d0e78&chksm=cfcf4a12f8b8c304943c6776e549b9e0db63a1bf71e7e52c8ca3037fb30a1208fba0cde7aded&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (32)南洋理工大学刘杨教授——网络空间安全和AIGC整合之道学习笔记及强推（InForSec）](http://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247499894&idx=1&sn=b13567ba9da2116544931b0b3b32fb0d&chksm=cfcf70bbf8b8f9ad60043155333761e2d3a828f6b5952b33b73545830442f0c27963d34a3521&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (33)NDSS2024 Summer系统安全和恶意代码分析方向相关论文汇总](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247500395&idx=1&sn=c5913a16bdde9fbbfcfddc3926296836&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (34)ESWA2024 基于SGDC的轻量级入侵检测系统](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501100&idx=1&sn=ea3de2aef633874c0c37a4410c27cdef&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (35)TIFS24 MEGR-APT：基于攻击表示学习的高效内存APT猎杀系统](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501201&idx=1&sn=709a7a8f892f19870b9ed0d31f4f57aa&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (36)C&S22 MPSAutodetect：基于自编码器的恶意Powershell脚本检测模型](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501253&idx=1&sn=7f467401adcf67cc67d7c2d3573e7c2e&scene=21#wechat_redirect)  
  
  
- [[AI安全论文] (37)CCS21 DeepAID：基于深度学习的异常检测（解释）](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501274&idx=1&sn=66f331dcd21faf0af18d06e3f0efd75a&scene=21#wechat_redirect)  
  
  
[[AI安全论文] (38)基于大模型的威胁情报分析与知识图谱构建论文总结（读书笔记）](https://mp.weixin.qq.com/s?__biz=Mzg5MTM5ODU2Mg==&mid=2247501812&idx=1&sn=e9a76f92ac90709cb30ad782df93aeb3&scene=21#wechat_redirect)  
  
  
- [AI安全论文] (39)EuroS&P25 CTINEXUS：基于大模型的威胁情报知识图谱自动构建  
  
****  
