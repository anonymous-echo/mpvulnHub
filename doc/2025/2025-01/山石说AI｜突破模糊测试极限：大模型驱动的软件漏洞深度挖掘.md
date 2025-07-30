#  山石说AI｜突破模糊测试极限：大模型驱动的软件漏洞深度挖掘   
原创 山石网科  山石网科新视界   2025-01-02 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnKvXxzN9syadS6NM2YvjAFg2NBLDqDGZVP1U0V8gHOVwgkjJ2wpWTDz4YRA2t8rlEWdxNWIhnnhpA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**【山石说AI】•第15篇**  
**大模型在网络安全中的最新应用进展（四）**  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
软件漏洞的发现向来是一场与时间的赛跑，而大模型的引入为模糊测试注入了全新的智慧动力。跳脱传统随机变异的局限，大模型精准的语言和逻辑推理能力正重新定义模糊测试的效率与深度，助力安全团队快速定位潜在威胁，为软件安全提供更强的护盾。  
  
  
传统的模糊测试技术在揭示软件漏洞方面虽有效，但其固有的局限性可能会影响测试的效率和效果。一个显著缺点是传统模糊测试器主要以随机或半随机的方式运行，这导致测试过程可能耗时且效果不佳，因为它们无法探索所有可能的执行路径。此外，用于变异的种子通常由人类手工构造，耗时较长。尽管多年来已对此类问题进行了研究，并提出了许多缓解方法，但大模型的出现为模糊测试领域带来了全新的思维方式。  
  
  
大模型模糊测试相较于传统方法的优势有哪些？  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NGIAw2Z6vnJ4c4vwZeQQBNsvib831tD8SiaYtLpZTSbRicaB2mQwSOicOzsHApwibA3WK4K7yPfHC16GY8QXwMXpBrA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Ying Z等人  
 [1]评估了ChatGPT在直接生成测试用例（无微调）方面的表现，并将其与两种传统测试工具（SIEGE和TRANSFER）进行了比较。他们的实验表明，当提供了漏洞的详细描述、可能的攻击方式以及代码上下文时，大模型的表现优于传统方法。以下是大模型相较传统工具的优势描述。一个重要因素在于大模型的出现使得模糊测试从随机变异转向引导式变异。Jie H等人  
 [2]向传统灰盒模糊测试添加了一个基于GPT的种子变异器，从种子池中选择种子并请求ChatGPT生成的变体以生成更高质量的输入。  
  
  
另一个优势是大模型具备良好的跨编程语言理解能力，因此能够在多个编程语言中执行测试任务。Chunqiu S X等人  
 [3]充分利用了大模型对不同编程语言的理解。大多数传统方法只能模糊测试特定的编程语言，而基于大模型的模糊测试可以涵盖不同的语言。他们使用名为Fuzz-Loop的方法测试了6种编程语言（C、C++、Go、SMT2、Java和Python）的代码，该方法能自动变异测试用例。大多数传统模糊测试方法难以覆盖所有代码，而掌握了代码逻辑的大模型可以针对低覆盖率代码生成更具针对性的测试用例。例如，Caroline L等人  
 [4]在SBST（基于搜索的软件测试，一种传统的模糊测试方法）达到覆盖率瓶颈时，使用Codex生成针对低覆盖率函数的测试用例。具体来说，Codex生成的原始字符序列被反序列化为SBST的内部测试用例表示，以利用SBST的变异操作和适应性函数。  
  
  
根据测试对象的不同，在使用大模型时策略可能需要适当调整。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/NGIAw2Z6vnJ4c4vwZeQQBNsvib831tD8SME4OtE4jYwxIr79NYxF1KiaUmoeGCoGNyUlDZzgvibUM2hvYIh0D8lhg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
对于一般API的测试，Cen Z等人  
 [5]分析方法进行了比较，发现大模型可以在较少的人工干预下自动生成大量有效的模糊测试驱动程序。该研究引入了查询策略、迭代改进和使用示例来提升大模型的表现。尽管这主要涉及API测试，但对于深度学习库的测试策略则需要进行调整。调用深度学习库的程序通常对张量维度有严格要求，否则模糊测试器会执行大量无意义的测试。  
  
  
Yinlin D等人  
 [6]提出了TitanFuzz，一种用于深度学习库的测试用例生成工具。他们的训练语料库包含大量调用深度学习库API的代码片段，因此可以隐式学习语言的语法/语义和复杂的深度学习API约束，以高效生成深度学习程序。另一项研究FuzzGPT（同样由Yinlin D等人进行）也关注深度学习库的模糊测试，与前一项研究不同，FuzzGPT侧重于利用历史触发错误的代码片段来指导大模型生成测试用例。  
  
  
除了上述研究外，我们还收集了一些针对其他测试对象的文献。针对协议的测试，Ruijie M等人  
 [7]讨论了如何在缺少机器可读的协议规范情况下查找协议实现中的安全漏洞。他们通过大量人类可读的协议文档对大模型进行训练，并要求大模型对协议交互消息进行变异，以实现协议模糊测试（如HTTP）。针对BusyBox的测试，Asmita等人  
 [8]专门针对在基于Linux的设备上广泛使用的BusyBox，提出了两种方法：利用大模型生成目标特定的初始种子以进行模糊测试，这显著提高了识别崩溃和潜在漏洞的效率；以及“崩溃重用”，利用之前获得的崩溃数据来优化新目标的测试流程。  
  
向上滑动，查看所有参考文献  
  
1.Ying Zhang, Wenjia Song, Zhengjie Ji, Danfeng, Yao, and Na Meng. How well does llm generate security tests? arXiv preprint arXiv:2310.00710, 2023.  
  
2.Jie Hu, Qian Zhang, and Heng Yin. Augmenting greybox fuzzing with generative ai. arXiv preprint arXiv:2306.06782, 2023.  
  
3.Chunqiu Steven Xia, Matteo Paltenghi, Jia Le Tian, Michael Pradel, and Lingming Zhang. Fuzz4all: Universal fuzzing with large language models. arXiv preprint arXiv:2308.04748, 2024.  
  
4.Caroline Lemieux, Jeevana Priya Inala, Shuvendu K. Lahiri, and Siddhartha Sen. Codamosa: Escaping coverage plateaus in test generation ·with pre-trained large language models. In 2023 IEEE/ACM 45th International Conference on Software Engineering (ICSE), pages 919–931, 2023.  
  
5.Cen Zhang, Mingqiang Bai, Yaowen Zheng, Yeting Li, Xiaofei Xie, Yuekang Li, Wei Ma, Limin Sun, and Yang Liu. Understanding large language model based fuzz driver generation. arXiv preprint arXiv:2307.12469, 2023.  
  
6.Yinlin Deng, Chunqiu Steven Xia, Haoran Peng, Chenyuan Yang, and Lingming Zhang. Large language models are zero-shot fuzzers: Fuzzing deep-learning libraries via large language models. In Proceedings of the 32nd ACM SIGSOFT International Symposium on Software Testing and Analysis, ISSTA 2023, page 423–435, New York, NY, USA, 2023. Association for Computing Machinery.  
  
7.Ruijie Meng, Martin Mirchev, Marcel Böhme, and Abhik Roychoudhury. Large language model guided protocol fuzzing. In Proceedings of the 31st Annual Network and Distributed System Security Symposium (NDSS), 2024.  
  
8.Asmita, Yaroslav Oliinyk, Michael Scott, Ryan Tsang, Chongzhou Fang, and Houman Homayoun. Fuzzing busybox: Leveraging llm and crash reuse for embedded bug unearthing. arXiv preprint arXiv:2403.03897, 2024.  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnIYnBoVjHn0mWO3pro1TfcNW1g9SygLH6FI0c8mzWjXzibo9E0zM28pwRHFqwdHGwa2KbdicjgWdTtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NGIAw2Z6vnL5RDiaSVOWztIUKyMT0bqdqga2kU6cW4mQMrFFjnJOWlwtexl1mLwI3a7VRXmqOmNvV0yCk5lzdBQ/640?wx_fmt=png&from=appmsg "")  
  
**“码”上阅读**  
  
**【山石说AI】全系列文章**   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请540多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/NGIAw2Z6vnIunOKIgoia7NibiaoWvRJIt9LFaW6icqVSicJzZqLlIicdic3LjTrIcsWc2D1GNia3YKcWWia53a0Z64X0u0A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
