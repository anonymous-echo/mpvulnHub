#  【论文速读】| EnStack：一种用于增强源代码漏洞检测的大语言模型集成堆叠框架   
原创 知识分享者  安全极客   2025-02-19 08:05  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
**原文标题:**EnStack: An Ensemble Stacking Framework of Large Language Models for Enhanced Vulnerability Detection in Source Code  
  
**原文作者:** Shahriyar Zaman Ridoy, Md. Shazzad Hossain Shaon, Alfredo Cuzzocrea, Mst Shapna Akter  
  
**作者单位:**  
- North South University, Dhaka, Bangladesh  
  
- Oakland University, Rochester, MI, USA  
  
- University of Calabria, Italy  
  
- University of Paris City, France  
  
**关键词:** CodeBERT, Ensemble Stacking, GraphCodeBERT, Large Language Models (LLMs), Source Code Analysis, UniXcoder, Vulnerability Detection  
  
**原文链接:** https://arxiv.org/abs/2411.16561  
  
**开源代码:** 暂无  
  
**论文要点**  
  
  
**论文简介：**  
  
在当今数字化时代，软件漏洞的自动检测对保障系统安全起着举足轻重的作用。然而，现代代码库的复杂性和多样性使得现有的检测方法面临诸多挑战。为了解决这一问题，本文提出了一种名为 EnStack 的创新集成堆叠框架，该框架借助自然语言处理（NLP）技术，显著提升了软件漏洞检测的效率和准确性。  
  
EnStack 框架巧妙地融合了多个在代码理解领域表现卓越的预训练大语言模型（LLM）。其中，CodeBERT 擅长语义分析，能够深入理解代码的内在含义；GraphCodeBERT 专注于结构表示，精确呈现代码的结构特征；UniXcoder 则具备强大的跨模态能力，可灵活处理多种模态的信息。  
  
在具体实现过程中，研究者首先利用 Draper VDISC 数据集对这些模型进行精细微调，使其更贴合漏洞检测任务。随后，通过逻辑回归、支持向量机（SVM）、随机森林和 XGBoost 等元分类器，将各模型的输出进行有效整合。这种方式使得 EnStack 能够捕捉到单个模型容易忽视的复杂代码模式和潜在漏洞。各元分类器充分发挥每个大语言模型的优势，共同构建了一个全面且强大的检测模型，使其在各种不同的编程环境中，都能精准地检测出细微而复杂的软件漏洞。  
  
大量的实验结果有力地证明了 EnStack 的优越性。与现有方法相比，EnStack 在准确率、精确率、召回率和 F1 分数等关键指标上均取得了显著提升。这项研究不仅揭示了集成大语言模型方法在代码分析任务中的巨大潜力，也为利用自然语言处理技术推动自动化漏洞检测的发展提供了极具价值的思路和方向。  
  
**研究目的：**  
  
本文提出了 EnStack 集成堆叠框架，旨在提升基于大语言模型（LLMs）的漏洞检测能力。具体研究目的如下：  
  
**1. 开发融合多种 LLM 的漏洞检测框架：**集成 CodeBERT、GraphCodeBERT 和 UniXcoder，发挥它们在代码分析中的语义分析、结构表示和跨模态处理优势；运用 Ensemble Stacking 技术，通过逻辑回归、SVM、随机森林、XGBoost 等元分类器整合多个 LLM 的预测结果，以提高检测精度。  
  
**2. 提升漏洞检测的准确性、召回率和泛化能力：**在 Draper VDISC 开源代码数据集（包含多种漏洞类型）上开展实验，验证 EnStack 在漏洞检测任务中的优越性；通过实验分析，探究不同 LLM 组合和元分类器对漏洞检测性能的影响。  
  
**3. 对比 EnStack 与现有方法的性能：**评估 EnStack 相较于单个 LLM 模型、传统机器学习方法（如 CNN、RNN、GNN）在漏洞检测任务中的提升；开展消融实验，分析最有效的模型组合，为后续研究提供指引。  
  
**研究贡献：**  
  
1. 提出一种基于集成的堆叠框架，该框架将多个预训练的大语言模型（LLMs）与元分类器相结合，以增强源代码中的漏洞检测能力。  
  
2. 在德雷珀 VDISC 数据集上对所提出的 EnStack 框架进行全面评估，结果表明，与单个模型和现有方法相比，该框架在准确率、精确率、召回率、F1 分数和 AUC 分数等指标上均具有卓越性能。  
  
3. 进行消融研究，分析不同模型组合和元分类器对检测性能的影响，深入探讨堆叠方法的有效性，并为未来模型集成策略的研究提供指导。  
  
**引言**  
  
  
在软件开发快速发展的当下，软件漏洞愈发常见，给各方带来严重安全威胁，传统检测方法难以应对现代软件系统的复杂规模，急需先进技术。大语言模型为代码分析带来新方向，像 CodeBERT、GraphCodeBERT 和 UniXcoder 等在相关任务取得成果，但在检测复杂软件漏洞上存在局限，当前基于大语言模型的方法侧重代码特定方面，单独使用无法全面涵盖漏洞多面性，早期深度学习模型也因依赖特定架构难以泛化不同漏洞类型。  
  
为此，本文提出基于集成的堆叠方法，整合 CodeBERT、GraphCodeBERT 和 UniXcoder，利用集成堆叠技术，在 Draper VDISC 数据集微调各模型，再用逻辑回归、支持向量机等元分类器组合输出，通过整合捕捉代码不同方面的模型，让元分类器找到组合预测的最优解，弥补单个模型不足，提升整体检测能力 。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SgrCFjqk267tvufJwPaKyiasz7SHGOVUbCvZibhy8eHZUegrWO8JwGtRPjJ0qcl8n2BITHnEFcicOvA/640?wx_fmt=png&from=appmsg "")  
  
**研究方法**  
  
  
检测源代码中的漏洞对于确保软件安全至关重要。为应对这一挑战，已提出各种模型，但要有效处理源代码的复杂结构仍需改进。在本研究中，研究者采用集成堆叠方法，结合多个大语言模型（LLM）的优势来提升漏洞检测能力。所使用的模型包括 CodeBERT、GraphCodeBERT 和 UniXcoder，研究者通过集成堆叠技术将它们的输出结果进行整合。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SgrCFjqk267tvufJwPaKyiaWtib4vMIbCvju59qj4WhXgKia7Qx4xJAxiboSgEgppiaqBtBEoxqAGvhbQ/640?wx_fmt=png&from=appmsg "")  
  
**研究实验**  
  
  
**A. 硬件与软件设置**  
  
所有实验均使用英伟达 Tesla P100 GPU 进行。研究者采用 PyTorch 深度学习框架来实现模型，并借助 Hugging Face 的 transformers 库对诸如 CodeBERT、GraphCodeBERT 和 UniXcoder 等预训练模型进行微调。对于集成堆叠技术，研究者运用 scikit-learn 来实现元分类器，包括逻辑回归、随机森林、支持向量机（SVM）和 XGBoost。  
  
**B. 基线模型**  
  
研究者将研究者的模型与多个基线模型进行比较，其中包括基于 Transformer 的模型，如 CodeBERT、GraphCodeBERT 和 UniXcoder。此外，研究者纳入了注意力长短期记忆网络（Attention LSTM）作为非 Transformer 基线模型，以凸显预训练语言模型在性能上的优势。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SgrCFjqk267tvufJwPaKyiaFu4cPPibygo4NUv9NKlYCh1YlmZCSCcONXdVXqw8mL16f7YFSjoBpAQ/640?wx_fmt=png&from=appmsg "")  
  
评估指标：研究者使用多个指标来评估模型的性能，包括：  
  
1. 准确率：正确预测的比例。  
  
2. 精确率、召回率和 F1 分数：精确率代表正预测的准确性，召回率衡量实际正例的覆盖程度，F1 分数则平衡了精确率和召回率。  
  
3. AUC 分数：计算受试者工作特征曲线下面积（AUC），以评估模型区分不同漏洞类别的能力。  
  
**C. 结果与分析**  
  
**1. 单个模型性能******  
  
研究者首先使用准确率、精确率、召回率、F1 分数和 AUC 分数评估了单个模型，包括注意力长短期记忆网络（Attention LSTM）、CodeBERT（C）、GraphCodeBERT（G）和 UniXcoder（U）。表三总结的这些结果突出了每个模型在检测源代码漏洞方面的独特优势与局限性。  
  
非 Transformer 基线模型注意力长短期记忆网络（Attention LSTM）的准确率达到 73.00%，这反映了它捕捉序列依赖关系的能力，但也表明其在处理代码中更复杂的语义和结构方面存在局限性。该模型 77.54% 的较低 AUC 分数进一步凸显了它在有效区分漏洞类别方面的困难。  
  
相比之下，基于 Transformer 的模型 CodeBERT 有显著提升，准确率达到 78.51%，F1 分数为 77.98%。它处理自然语言和编程代码语义的能力促成了这些提升，不过其相对较低的召回率（78.51%）表明，它可能无法完全捕捉到漏洞检测所必需的结构细节。  
  
GraphCodeBERT（G）整合了代码语义和结构信息，表现优于 CodeBERT，准确率为 80.05%，F1 分数为 79.86%，AUC 分数更高，达到 93.36%。该模型对代码流和数据依赖关系的更深入理解，使其在识别漏洞方面更为稳健。  
  
UniXcoder（U）在单个模型中性能最佳，准确率为 81.54%，F1 分数为 81.49%。UniXcoder 通过跨模态学习来表示代码的句法和语义属性的能力，使其超越了其他模型。其 93.80% 的 AUC 分数是所有模型中最高的，凸显了它区分不同类别漏洞的卓越能力。  
  
**2. 单个大语言模型（LLM）与元分类器的堆叠**  
  
研究者探究了将单个大语言模型（LLM）与传统机器学习元分类器（如逻辑回归（LR）、支持向量机（SVM）、随机森林（RF）和 XGBoost）进行堆叠的影响。结果表明，堆叠相较于单个模型提升了性能。例如，将 UniXcoder 与 SVM 堆叠后，准确率达到 81.36%，F1 分数为 81.89%，而独立的 UniXcoder 模型则达不到这样的成绩。同样，将 GraphCodeBERT 与逻辑回归堆叠后，准确率达到 80.13%，这进一步说明了将大语言模型（LLM）与元分类器相结合的优势。  
  
这些发现表明，即使不借助多个大语言模型（LLM），单个大语言模型（LLM）也可以通过传统分类器得到有效增强，优化其预测并提高其区分能力。在元分类器中，SVM 由于能够处理高维特征空间，始终表现出色。  
  
**3. 多个大语言模型（LLM）与元分类器的集成堆叠**  
  
然而，最显著的性能提升出现在以集成堆叠方式组合多个大语言模型（LLM）时。将 GraphCodeBERT 和 UniXcoder（G + U）与 SVM 堆叠，实现了 82.36% 的最高准确率和 82.28% 的最佳 F1 分数。这一结果强调了将 GraphCodeBERT 的结构洞察与 UniXcoder 的跨模态学习相结合的有效性，使元分类器能够利用两个模型的优势。  
  
通过将 G + U 与逻辑回归堆叠，实现了 92.85% 的最高 AUC 分数，表明该模型在不同类别间具有卓越的区分能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SgrCFjqk267tvufJwPaKyiaXRRJYpmV1TjicJI5s5EUZyJfvD99TvSibvrpfK7icbWYGaDcvU9Xn4zxw/640?wx_fmt=png&from=appmsg "")  
  
**D. 消融研究**  
  
**1. 堆叠中模型组合的影响**  
  
研究者对堆叠集成中的各种模型组合进行了详细分析，重点关注 CodeBERT（C）、GraphCodeBERT（G）和 UniXcoder（U）。如图 4（a）所示，与其他模型组合相比，在不同的元分类器中，GraphCodeBERT 和 UniXcoder 的堆叠（堆叠 G + U）始终表现出卓越的性能。具体而言，将 G + U 与 SVM 堆叠，达到了 82.36% 的最高准确率和 82.28% 的 F1 分数，显著优于像 C + G 这样的堆叠组合，后者与 SVM 堆叠时准确率较低，仅为 81.46%。这表明将 GraphCodeBERT 的结构洞察与 UniXcoder 的句法 - 语义理解相结合，可产生更全面的特征集，优化用于漏洞检测的堆叠集成的性能。这些结果强调了选择互补的基础模型以最大化堆叠有效性的重要性。  
  
**2. 堆叠中元分类器选择的影响**  
  
除了模型组合，研究者还研究了不同元分类器（包括逻辑回归（LR）、随机森林（RF）、支持向量机（SVM）和 XGBoost）对堆叠集成性能的影响。如图 4（b）所示，元分类器的选择对性能有显著影响。在相同配置下，将 G + U 与 SVM 堆叠产生了最高的 F1 分数（82.28%）和精确率（82.85%），而逻辑回归则实现了最高的 AUC 分数（92.85%）。相比之下，XGBoost 始终表现不佳，当堆叠 G + U 时，准确率仅为 80.67%。这表明像 SVM 和 LR 这样的线性分类器更适合在这项任务中利用基础模型的互补特征。像 XGBoost 这样更复杂的分类器可能会引入不必要的复杂性，却无法转化为更好的性能，这进一步验证了简单、可解释的分类器在该应用中的适用性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8SgrCFjqk267tvufJwPaKyiaXo6B5Vc60upguvBHPfYzYhc2ufJ8nsPf5ZtcugcbBXW9P1EsMmgWvg/640?wx_fmt=png&from=appmsg "")  
  
**E. 讨论**  
  
**1. 用于漏洞检测的集成堆叠**  
  
研究者的实验结果表明，结合多个基于 Transformer 模型优势的集成堆叠方法，在检测源代码漏洞方面优于单个模型。单个模型，如 CodeBERT、GraphCodeBERT 和 UniXcoder，取得了不错的准确率和 F1 分数，其中 UniXcoder 表现最佳，准确率为 81.54%。然而，通过加权聚合和堆叠相结合的方式组合这些模型，显著提升了整体性能。集成方法，特别是将 G + U 与逻辑回归（LR）和支持向量机（SVM）堆叠，实现了 82.36% 的最高准确率，展示了整合不同模型优势的价值。SVM 表现更为出色，达到了 82.28% 的最高 F1 分数，而逻辑回归则以 92.85% 的 AUC 分数展现出卓越的区分能力。这些结果突出了集成堆叠在改进漏洞检测方面的有效性，尤其是通过利用互补特征，如 UniXcoder 的句法 - 语义跨模态理解和 GraphCodeBERT 的结构洞察。  
  
**2. 局限性**  
  
EnStack 框架存在一些局限性。首先，数据集存在严重的类别不平衡问题，像 CWE - 469（整数溢出）等漏洞的代表性严重不足，降低了模型的有效泛化能力。为缓解这种不平衡而采用的下采样进一步减小了数据集规模，加剧了泛化挑战。其次，对 Draper VDISC 数据集的依赖限制了其适用性，因为该数据集专注于特定的漏洞和编程语言，对于推广到可能呈现不同漏洞模式的其他数据集和语言存在担忧。第三，集成堆叠方法带来了巨大的计算开销，预训练模型（CodeBERT、GraphCodeBERT、UniXcoder）的整合以及元分类器的训练都需要大量资源，限制了其在实时或大规模应用中的可扩展性。  
  
**论文结论**  
  
  
在本研究中，研究者提出了一种集成堆叠方法，将基于 Transformer 的模型（如 CodeBERT、GraphCodeBERT 和 UniXcoder）的输出与元分类器相结合，以改进源代码中的漏洞检测。通过在 Draper VDISC 数据集上对每个模型进行微调，并同时使用集成和堆叠方法，研究者证明了集成堆叠方法显著提升了单个模型的性能。在元分类器中，逻辑回归（LR）和支持向量机（SVM）产生了最佳结果，准确率达到 82.36%，并获得了 92.85% 的高 AUC 分数。这些结果验证了利用捕捉代码不同方面（句法、语义和结构）的多种模型来改进多类别环境中漏洞分类的有效性。  
  
尽管研究者的 EnStack 框架取得了有前景的结果，但在应对漏洞检测中代表性不足类别所带来的挑战方面仍有改进空间。在未来的工作中，研究者计划使用多个漏洞数据集进行实验，以评估研究者的模型在不同代码库中的泛化性和稳健性。通过纳入更广泛的数据集，研究者旨在捕捉更广泛的漏洞类型和模式，增强模型检测罕见和复杂问题的能力。此外，研究者打算探索诸如 LLaMA 和 Mistral 等生成式模型，以增强代码理解和漏洞检测能力。这些模型凭借其强大的生成能力，可用于特定领域的预训练，从而更全面地检测细微的漏洞。另外，研究者旨在研究生成式模型如何提供更丰富的代码上下文信息，有可能生成合成代码片段来扩充训练数据并提高模型的稳健性。探索这些生成式模型的迁移学习，将进一步使研究者能够定制检测策略，从而实现更准确、细致的漏洞识别。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QmV8xmuDmWRS7dWGRa4sgKPkkH2icicFib9SKIQ1ee0tEJI3vXk9dD4EQ91ano9DPrDv0bXKQopibrfw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
