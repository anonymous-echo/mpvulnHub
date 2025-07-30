#  【论文速读】| CleanVul：利用大语言模型启发式方法在代码提交中进行自动的函数级漏洞检测   
原创 知识分享者  安全极客   2025-02-13 10:06  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QmTLhv0jB8GS6Wtic69pG44V8Gib7ccD3FZolnOVkdOPafA3YULibw9S5AEkdO8sstRLGNFVDj7SgRg/640?wx_fmt=jpeg&from=appmsg "")  
  
**基本信息**  
  
  
**原文标题：**CleanVul: Automatic Function-Level Vulnerability Detection in Code Commits Using LLM Heuristics  
  
**原文作者**  
**：**Yikun Li, Ting Zhang, Ratnadira Widyasari 等  
  
**作者单位：**新加坡管理大学  
  
**关键词：**漏洞检测、函数级分析、大语言模型（LLM）、代码提交、数据集  
  
**原文链接：**https://arxiv.org/pdf/2411.17274  
  
**开源代码：**https://github.com/yikun-li/CleanVul  
  
**论文要点**  
  
  
**论文简介：**  
当前，软件漏洞的检测与修复是网络安全领域的重要议题之一，而训练机器学习模型以自动化检测漏洞是现代网络安全的趋势。  
本文发现现有的数据集（如从国家漏洞数据库 NVD 或 GitHub 中提取的数据）中存在大量噪声，噪声比例高达40%-75%。  
这些噪声主要源于自动标注方法将所有漏洞修复提交（VFCs）的修改均视为漏洞相关，而实际上，这些更改中许多与安全无关。  
  
为了应对这一问题，作者提出了一种新方法：结合大语言模型（LLM）和启发式规则来自动识别真正的漏洞修复修改，并构建了一个高质量的数据集CleanVul。实验表明，CleanVul的数据质量显著优于传统数据集（如PrimeVul和SVEN），并大幅提升了机器学习模型的性能和泛化能力。  
  
**研究目的：**  
研究的主要目的是解决现有漏洞数据集噪声过高的问题。  
这些噪声不仅影响模型的训练效果，还可能导致误报和漏报的增加，从而降低漏洞检测系统的实际可靠性。  
本论文的目标在于：  
  
1. 显著减少数据集中的噪声，通过过滤非漏洞相关的代码更改，改善训练数据的纯净度。  
  
2. 提高漏洞检测数据集的可用性，尤其是能从GitHub等非结构化来源中提取高质量数据，而非依赖于传统的NVD链接或手工标注。  
  
3. 为漏洞检测模型提供泛化能力更强的训练数据，以支持多种编程语言和复杂场景下的漏洞检测任务。  
  
**研究贡献：**  
本文的核心贡献包括以下几点：  
  
1. 漏洞修复提交的代码变更分类：通过手动分析，系统性地对漏洞修复提交中的非漏洞相关更改进行分类，提出了一种新的分类法，包括测试相关、错误修复、支持更改、代码重构和文档更新等类别，揭示了这些更改对数据集纯净度的影响。  
  
2. VulSifter方法：开发了一种结合LLM和启发式规则的全新方法，用于函数级漏洞修复更改的自动识别和过滤。在此过程中，LLM负责理解代码语义，启发式规则则用于排除无关的代码更改（如测试代码）。  
  
3. CleanVul数据集：构建了一个包含11,632个函数的高质量数据集，漏洞识别准确性（Correctness）高达90.6%，显著优于现有主流数据集，如SVEN（94.0%）和PrimeVul（86.0%）。  
  
4. 性能评估与对比：通过一系列实验验证，表明在CleanVul上训练的模型在准确性和泛化能力上均优于其他高质量数据集。  
  
**引言**  
  
  
在网络安全领域，漏洞的准确检测与修复至关重要。漏洞数据集是训练机器学习模型的关键资源，但现有数据集普遍存在噪声问题。例如，大量的GitHub代码提交被错误地标记为漏洞修复，更改中包含的测试代码、代码重构和文档更新等非漏洞相关内容干扰了模型的训练。这种噪声的存在严重降低了数据集的实际有效性，阻碍了自动化漏洞检测技术的发展。  
  
作者指出，当前的方法在处理GitHub代码库中的漏洞修复提交时面临显著挑战。传统方法依赖NVD描述的链接信息，但许多漏洞修复提交并未关联NVD记录，导致这些方法的适用范围受限。此外，自动标注方法缺乏对代码语义和上下文的理解能力，无法正确识别真正的漏洞修复更改。本文通过引入LLM和启发式规则的结合方法，从根本上改善了这一问题。  
  
**启发示例**  
  
  
作者以一个实际的GitHub提交为例，展示了现有方法难以区分漏洞修复和无关更改的复杂性。例如，ThingsBoard项目中的一个提交修复了XSS漏洞，但同时还包括了一些无关的代码修改，如删除冗余导入和更新许可证。这类“纠缠提交”往往包含多个目的的更改，这对传统的自动标注方法构成了挑战。通过该案例，作者进一步说明了需要精确区分漏洞相关与无关更改的必要性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HricGPESofYjLGeeLlb4kEXw9LKXeic7V7CmZbPibz5G5UNPBToZBUkv1w/640?wx_fmt=png&from=appmsg "")  
  
**VulSifter: 方法**  
  
  
VulSifter通过两阶段的框架完成漏洞修复更改的识别：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HI34nC9tEeHUXxBY763fHZFC0ggxnpD57s99cGlg4OQ6cQku65z7Iwg/640?wx_fmt=png&from=appmsg "")  
  
**1. LLM分析：**利用大语言模型分析代码片段的语义和上下文，将每个更改评分（0-4分），分数越高代表漏洞修复的可能性越大。  
  
**2. 启发式过滤：**根据常见的测试代码命名规则（如函数名或文件名中包含“test”）过滤测试相关的代码更改。实验表明，这种过滤策略显著提高了数据集的纯净度。  
  
**CleanVul: 数据集管理**  
  
  
作者从GitHub的127,063个代码库中抓取了超过530万次提交，并通过关键词匹配识别了59,687个漏洞修复提交。通过VulSifter的过滤和评分后，最终生成了一个高质量的数据集CleanVul。根据评分阈值的不同，CleanVul数据集分为多个等级（如阈值4代表最高质量的漏洞修复数据）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HibEiav2ib6sicIG8OKbQTsv5Dr1koFABwe4398QdyePTyPqSttKamaHUsQ/640?wx_fmt=png&from=appmsg "")  
  
**评估设置**  
  
  
研究设计了三个核心问题以评估方法的有效性：  
  
1. CleanVul相较于未经处理的数据集，正确性（Correctness）的提升有多大？  
  
2. 基于CleanVul微调的模型与其他主流数据集相比，在泛化能力上表现如何？  
  
3. CleanVul数据集的质量对模型性能提升的贡献有多大？  
  
**评估实验**  
  
  
**1. CleanVul的正确性提升：**在CleanVul上应用VulSifter后，数据集的正确性从28.7%显著提升至90.6%，表明该方法有效降低了噪声水平。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HythUZjhL0D6b45M5ImukvFTO8ODKX686BHXW5MGpy7EAcKS2J9UIfg/640?wx_fmt=png&from=appmsg "")  
  
**2. 跨数据集对比：**在CleanVul上训练的模型，在PrimeVul和SVEN数据集上的测试结果均优于这些数据集自身的原生模型，显示了CleanVul的优越泛化能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HWKxGkV4noeuG16HXYSHxR3mRyaCI4rKwqItFITyrVRBVczS9mXicB3w/640?wx_fmt=png&from=appmsg "")  
  
**3. 与未清理数据集对比：**CleanVul相比未清理数据集，不仅在模型的准确性上有显著提升（68.96%对55.23%），还在跨语言和跨平台测试中展现了更好的性能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6H2FvcBRXlxMnzavX1g1wN7y0Ir2ZMmBC9icMpjHqtE1yBO2sLh2pL9iaw/640?wx_fmt=png&from=appmsg "")  
  
**额外分析**  
  
  
在额外分析中，作者主要从敏感性、消融实验、评分机制和启发式规则的作用等角度，全面验证了VulSifter方法的有效性。  
  
首先，敏感性分析显示，上下文信息和提交消息对模型性能至关重要。去除上下文信息后，F1评分从82.24%降至77.64%，去除提交消息后降至81.17%，而同时去除两者时，F1评分进一步下降到76.00%。这表明，上下文与提交消息共同提供了关键的辅助信息，显著提高了漏洞修复检测的准确性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QuJ6kAq6JnjoasBZTsCg6HFkVCQVfAuzkJyK6F3WuRcME1Na1FoX89Pu35nRWeuXD65oNtIkiaFvw/640?wx_fmt=png&from=appmsg "")  
  
其次，消融实验验证了细粒度评分机制和启发式规则的贡献。细粒度评分（0-4分）相比简单二分类，F1评分提升了7.58%（从74.66%至82.24%），体现了评分机制在处理边界模糊样本时的优势。此外，启发式规则在排除测试相关噪声时也发挥了重要作用，去除启发式规则后F1评分下降至78.97%。  
  
最后，数据集质量随阈值提升而显著提高。阈值为4时，数据集Correctness达到97.3%，为最高质量子集；而较低阈值（如1）虽然覆盖更广，但噪声较高。这些结果充分说明VulSifter方法在减少数据噪声、提高模型性能和泛化能力上的价值，为未来研究奠定了坚实基础。  
  
**论文结论**  
  
  
CleanVul通过结合LLM与启发式规则，为函数级漏洞检测提供了全新的解决方案。相比现有数据集，CleanVul显著降低了数据噪声，提高了模型的训练效果和泛化能力。未来，作者计划扩展方法对多种编程语言的适配能力，并进一步优化启发式规则，以应对更多复杂场景。  
  
[](https://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247495405&idx=1&sn=67249648d5c312b5c178b23b077d28f3&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8QmV8xmuDmWRS7dWGRa4sgKPkkH2icicFib9SKIQ1ee0tEJI3vXk9dD4EQ91ano9DPrDv0bXKQopibrfw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493750&idx=1&sn=27bd578179e5abbdc8907b669519bb8f&chksm=c2b95d82f5ced4945cf8844013563398cb3a885ea96a2ee2b60bfcc26d77ebffe78a35285646&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493759&idx=1&sn=0aed37ae210bde25a6b16a745301b71d&chksm=c2b95d8bf5ced49d12eb8cc6192c4e091bf11b6ffe99d4025467ea98b9d04cad89ba0ea91710&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzkzNDUxOTk2Mw==&mid=2247493770&idx=1&sn=2c6d24403cda8f0ef45cadb10e1bfebd&chksm=c2b95d7ef5ced4686e39951e21153c81f0a1e57cabf0937e0d996e6621385745d3ee30d98c11&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8Q8ZzB8H1iavVTGLzQKrmiaV9ZINGu1cbRLSnUrgib5SPL2ibfOu7IicnWewfFoticsJsNECqJXia5mV8tWw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
