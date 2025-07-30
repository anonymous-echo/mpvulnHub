#  山石说AI｜精准探测 智慧守护：大模型重塑漏洞检测新标杆   
原创 山石网科  山石网科新视界   2025-01-06 06:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnKvXxzN9syadS6NM2YvjAFg2NBLDqDGZVP1U0V8gHOVwgkjJ2wpWTDz4YRA2t8rlEWdxNWIhnnhpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**【山石说AI】•第16篇**  
**大模型在网络安全中的最新应用进展（五）**  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
漏洞检测是网络安全的“侦查兵”，而大模型则为这一领域增添了革命性的技术活力。从深度语义理解到精准漏洞定位，大模型正在重新书写检测规则，为安全从业者提供更强大的技术武器，让防线更智慧、更高效。  
  
  
本节概述了利用大模型进行漏洞检测的关键研究文献。通过分析这些研究成果，我们旨在阐明在利用大模型提升网络安全方面的进展、挑战和未来方向。（在本文中，我们不严格区分漏洞和软件缺陷）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**大模型是否具备检测漏洞的能力？**  
  
  
以下几篇文献对这个问题进行了基础研究。尽管由于使用的数据集不同等原因，它们的结论存在差异，但总体上都表明大模型在漏洞检测问题上具有良好的前景。在早期阶段，Anton C等人  
 [1]测试了GPT-3和GPT-3.5在识别Java代码中的已知CWE漏洞方面的表现。结果显示，大模型在漏洞检测任务中的应用效果并不理想，需要进一步优化和研究。另一项研究中，Moumita D等人  
 [2]使用大模型（包括GPT-3.5、CodeGen和GPT-4）分析了几种常见漏洞（如SQL注入、溢出），结果表明尽管大模型确实具有检测漏洞的能力，但误报率较高。  
  
  
然而，Marwan O  
 [3]通过在各种含有漏洞代码的基准数据集上对GPT进行了微调，取得了良好的表现。类似地的结论，大模型（包括GPT-4和CodeLlama）在漏洞检测方面通常优于现有的静态分析和基于深度学习的工具。精心设计的提示在合成数据集上可获得理想结果，但在更具挑战性的真实数据集上表现下降。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NGIAw2Z6vnJ4c4vwZeQQBNsvib831tD8SGncu4Gdpxjb4QgeQTKJial2dJVhibRVgXBOx93LFMJLDXKWX7c9OCx6g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Rasmus I T J等人  
 [4]比较了多种开源和专有模型在Python代码片段上协助漏洞发现的表现，研究表明大模型可以有效提高代码审查的效率和质量，特别是在检测软件代码中的安全问题方面。Alexey S等人  
 [5]对WizardCoder进行了漏洞检测任务的微调，并探讨了性能限制是否因CodeBERT类模型的能力限制所致，结果显示大模型在漏洞检测方面前景广阔。Haonan L等人  
 [6]提出了LLift，一个利用大模型辅助静态程序分析的框架，专门用于检测未初始化使用（UBI）缺陷。LLift与静态分析工具和大模型接口，在实际场景中显示出50%的精确率，并在Linux内核中发现了13个先前未知的UBI漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**通过不同策略提高检测能力**  
  
  
与直接向大模型提供代码并请求答案不同，许多研究采用了不同的策略。一部分研究人员认为，仅提供代码并不足够，即代码需要进一步预处理或提供更多信息来协助大模型进行漏洞推理。Jin W等人  
 [7]未直接将代码提供给模型，而是进行了代码序列嵌入（Code Sequence Embedding, CSE），结合了代码的抽象语法树（AST）、数据流图（DFG）和控制流图（CFG）作为模型的输入，并借助Conformer机制（Transformer的一种改进架构）捕获输入的语义信息。  
  
  
Chenyuan Z等人  
 [8]不仅向GPT提供了代码，还加入了API调用序列和数据流图。Atieh B等人  
 [9]进行了类似实验，比较了模型在不同信息量条件下的表现（直接询问漏洞位置、在询问前提供部分CWE信息、在告知模型代码中的漏洞类型后再询问位置）。Noble S M等人  
 [10]专注于Android平台漏洞，比较了大模型在三种条件下的表现：直接要求模型寻找漏洞、在询问前提供漏洞摘要、在仅提供APK的核心文件（如AndroidManifest.xml和MainActivity.java）后允许大模型请求所需文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NGIAw2Z6vnJ4c4vwZeQQBNsvib831tD8Sliay3s8qibI3wr2ACmNVRDCGd1LiaqhvZrsRFIW6l0XyMMVbGU4x6MW4Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
除了上述方法外，研究人员还提出了一些创新理念来提升大模型的漏洞检测能力。Sihao H等人  
 [11]提出了一个创新的两阶段框架GPTLENS，包括两个对抗代理角色：审计员和评论员。审计员在生成阶段识别智能合约中的潜在漏洞，评论员在识别阶段评估审计员生成的漏洞。Zhihong L等人  
 [12]使用传统算法（TF-IDF和BM25）将待分析代码与漏洞语料库中的代码匹配相似度。待分析代码与语料库中的相似代码一起被提供给大模型，利用上下文学习（In-Context learning）理念，大模型能够更好地分析其是否属于此类漏洞。专为智能合约漏洞检测设计，Yuqiang S等人  
 [13]提出了GPTScan工具。GPTScan首先解析智能合约项目，确定函数的可达性，仅保留潜在的漏洞函数，然后使用GPT将候选函数与预定义漏洞类型匹配，最后让GPT验证漏洞。  
  
  
为增强大模型的漏洞推理能力，Yuqiang S等人  
 [14]提出了LLM4Vuln，分离大模型的漏洞推理能力（例如，主动获取附加信息、运用相关漏洞知识、遵循指令输出结构化结果）。他们允许大模型请求目标代码的附加上下文信息，并得出结论，即并非提供的信息越多性能越好。例如，完整的漏洞报告、大量调用上下文等过多信息可能导致分心。Zhenyu M等人  
 [15]提出了一种新方法MuCoLD，该方法模拟漏洞检测中的多角色代码审查过程，通过扮演开发者和测试人员等角色，促使大模型进行讨论，以达成对漏洞的存在和分类的共识。该方法从二进制判断和推理开始，通过迭代对话不断优化评估结果。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NGIAw2Z6vnJ4c4vwZeQQBNsvib831tD8SME4OtE4jYwxIr79NYxF1KiaUmoeGCoGNyUlDZzgvibUM2hvYIh0D8lhg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
目前主流思路是检测特定程序中的漏洞，但也有研究尝试利用大模型从漏洞中推测受影响的库列表。Tianyu C等人  
 [16]发现许多NVD中的漏洞报告未列出或列出不完整、错误的受影响库名称，这增加了第三方库漏洞的风险。为此，他们提出了名为VulLibGen的方法，旨在检测第三方库中的漏洞。VulLibGen仅使用漏洞描述作为输入，利用大模型的先验知识生成受影响库的名称列表。  
  
  
与前述研究方向不同，Peiyu L等人  
 [17]提出了一种应用ChatGPT进行漏洞管理的方法，评估其在预测安全漏洞、评估严重性、修复漏洞和验证补丁正确性方面的能力。研究表明，虽然ChatGPT可辅助识别和缓解软件安全威胁，但在漏洞优先级排序和补丁验证等任务上仍有改进空间。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**数据集准备**  
  
  
除了重新训练或微调模型的方法外，数据集的构建也是关键环节之一。Yizheng C等人  
 [18]提出了一个新型漏洞源代码数据集DiverseVul，包含18,945个漏洞函数（涵盖150个CWE）和330,492个正常函数，所有样本均为C/C++代码。  
  
  
此外，他们讨论了11种不同的深度学习架构，并得出结论，尽管大模型取得了一定的成功，但模型在漏洞检测方面仍面临高误报率、低F1分数和难以检测复杂CWE等挑战。Norbert T等人  
 [19]生成了一个包含112,000个含漏洞的C代码的数据集，详细标注了漏洞信息（CWE编号、位置和函数名称），该数据集中的所有代码均由GPT-3.5生成。Zeyu G等人  
 [20]提出了一个综合性漏洞基准数据集VulBench，包含来自CTF挑战和实际应用的高质量数据，并为每个漏洞函数提供详细的漏洞类型和成因注释。  
  
  
向上滑动，查看所有参考文献  
  
1.Anton Cheshkov, Pavel Zadorozhny, and Rodion Levichev. Evaluation of chatgpt model for vulnerability detection. arXiv preprint arXiv:2304.07232, 2023.  
  
2.Moumita Das Purba, Arpita Ghosh, Benjamin J. Radford, and Bill Chu. Software vulnerability detection using large language models. In 2023 IEEE 34th International Symposium on Software Reliability Engineering Workshops (ISSREW), pages 112–119, 2023.  
  
3.Marwan Omar. Detecting software vulnerabilities using language models. arXiv preprint arXiv:2302.11773, 2023.  
  
4.Rasmus Ingemann Tuffveson Jensen, Vali Tawosi, and Salwa Alamir. Software vulnerability and functionality assessment using llms. arXiv preprint arXiv:2403.08429, 2024.  
  
5.Alexey Shestov, Rodion Levichev, Ravil Mussabayev, and Anton Cheshkov. Finetuning large language models for vulnerability detection. arXiv preprint arXiv:2401.17010, 2024.  
  
6.Haonan Li, Yu Hao, Yizhuo Zhai, and Zhiyun Qian. The hitchhiker’s guide to program analysis: A journey with large language models. arXiv preprint arXiv:2308.00245, 2023.  
  
7.Jin Wang, Zishan Huang, Hengli Liu, Nianyi Yang, and Yinhao Xiao. Defecthunter: A novel llm-driven boosted-conformer-based code vulnerability detection mechanism. arXiv preprint arXiv:2309.15324, 2023.  
  
8.Chenyuan Zhang, Hao Liu, Jiutian Zeng, Kejing Yang, Yuhong Li, and Hui Li. Prompt-enhanced software vulnerability detection using chatgpt. arXiv preprint arXiv:2308.12697, 2023.  
  
9.Atieh Bakhshandeh, Abdalsamad Keramatfar, Amir Norouzi, and Mohammad Mahdi Chekidehkhoun. Using chatgpt as a static application security testing tool. arXiv preprint arXiv:2308.14434, 2023.  
  
10.Noble Saji Mathews, Yelizaveta Brus, Yousra Aafer, Mei Nagappan, and Shane McIntosh. Llbezpeky: Leveraging large language models for vulnerability detection. arXiv preprint arXiv:2401.01269, 2024.  
  
11.Sihao Hu, Tiansheng Huang, Fatih Ilhan, Selim Furkan Tekin, and Ling Liu. Large language model-powered smart contract vulnerability detection: New perspectives. arXiv preprint arXiv:2310.01152, 2023.  
  
12.Zhihong Liu, Qing Liao, Wenchao Gu, and Cuiyun Gao. Software vulnerability detection with gpt and in-context learning. In 2023 8th International Conference on Data Science in Cyberspace (DSC), pages 229–236, 2023.  
  
13.Yuqiang Sun, Daoyuan Wu, Yue Xue, Han Liu, Haijun Wang, Zhengzi Xu, Xiaofei Xie, and Yang Liu. Gptscan: Detecting logic vulnerabilities in smart contracts by combining gpt with program analysis. arXiv preprint arXiv:2308.03314, 2023.  
  
14.Yuqiang Sun, Daoyuan Wu, Yue Xue, Han Liu, Wei Ma, Lyuye Zhang, Miaolei Shi, and Yang Liu. Llm4vuln: A unified evaluation framework for decoupling and enhancing llms’ vulnerability reasoning. arXiv preprint arXiv:2401.16185, 2024.  
  
15.Zhenyu Mao, Jialong Li, Munan Li, and Kenji Tei. Multi-role consensus through llms discussions for vulnerability detection. arXiv preprint arXiv:2403.14274, 2024.  
  
16.Tianyu Chen, Lin Li, Liuchuan Zhu, Zongyang Li, Guangtai Liang, Ding Li, Qianxiang Wang, and Tao Xie. Vullibgen: Identifying vulnerable third-party libraries via generative pre-trained model. arXiv preprint arXiv:2308.04662, 2023.  
  
17.Peiyu Liu, Junming Liu, Lirong Fu, Kangjie Lu, Yifan Xia, Xuhong Zhang, Wenzhi Chen, Haiqin Weng, Shouling Ji, and Wenhai Wang. How chatgpt is solving vulnerability management problem. arXiv preprint arXiv:2311.06530, 2023.  
  
18.Yizheng Chen, Zhoujie Ding, Lamya Alowain, Xinyun Chen, and David Wagner. Diversevul: A new vulnerable source code dataset for deep learning based vulnerability detection. In Proceedings of the 26th International Symposium on Research in Attacks, Intrusions and Defenses, RAID ’23, page 654–668, New York, NY, USA, 2023. Association for Computing Machinery.   
  
19.Norbert Tihanyi, Tamas Bisztray, Ridhi Jain, Mohamed Amine Ferrag, Lucas C. Cordeiro, and Vasileios Mavroeidis. The formai dataset: Generative ai in software security through the lens of formal verification. In Proceedings of the 19th International Conference on Predictive Models and Data Analytics in Software Engineering, PROMISE 2023, page 33–43, New York, NY, USA, 2023. Association for Computing Machinery.  
  
20.Zeyu Gao, Hao Wang, Yuchen Zhou, Wenyu Zhu, and Chao Zhang. How far have we gone in vulnerability detection using large language models. arXiv preprint arXiv:2311.12420, 2023.  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnIYnBoVjHn0mWO3pro1TfcNW1g9SygLH6FI0c8mzWjXzibo9E0zM28pwRHFqwdHGwa2KbdicjgWdTtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NGIAw2Z6vnL5RDiaSVOWztIUKyMT0bqdqga2kU6cW4mQMrFFjnJOWlwtexl1mLwI3a7VRXmqOmNvV0yCk5lzdBQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**“码”上阅读**  
  
**【山石说AI】全系列文章**   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批科创板上市公司的身份，在2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请540多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnIunOKIgoia7NibiaoWvRJIt9LFaW6icqVSicJzZqLlIicdic3LjTrIcsWc2D1GNia3YKcWWia53a0Z64X0u0A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
