> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247492693&idx=1&sn=f912973994e379d3c80bed9b2187214b

#  中山大学｜FORGE：驱动大语言模型自动化构建大规模智能合约漏洞数据集  
原创 申一鸣@中山大学  安全学术圈   2025-06-28 01:14  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56uWvqaOr6FPeDtVwAka72ZGYkVbtjayrprrTKHsEep5mtV76NQxTHRtQ/640?wx_fmt=png&from=appmsg "")  
  
原文标题：FORGE: An LLM-driven Framework for Large-Scale Smart Contract Vulnerability Dataset Construction  
原文作者：Jiachi Chen, Yiming Shen, Jiashuo Zhang*, Zihao Li, John Grundy, Zhenzhe Shao, Yanlin Wang, Jiashui Wang, Ting Chen, Zibin Zheng  
原文链接：https://arxiv.org/pdf/2506.18795  
发表会议：ICSE'26  
笔记作者：申一鸣@中山大学  
主编：黄诚@安全学术圈  
## 研究背景  
  
面对日益频发的链上安全事件，当前智能合约生态系统在安全防护方面的脆弱性愈发凸显。其中，构建**高质量漏洞数据集**  
是评估安全工具、推动安全研究的重要基础。但现有数据集构建方法面临双重困境：**首先是人工构建过程低效且易错**  
，传统人工标注方式不仅耗费大量人力资源（如DAppSCAN数据集消耗44个人月），还存在标注错误风险，导致数据集规模受限、质量参差且更新滞后；**其次是缺乏统一的分类标准**  
，目前不同数据集采用各自的漏洞分类体系，如SWC、DASP10等标准，造成同一类漏洞在不同数据集中被标注为"Front-running"、"TOD"或"Block Manipulation"等不同名称，严重阻碍了相关研究和评估工作的开展。  
  
为此，本研究应用大语言模型（LLM）取代数据集构建过程中的劳动密集型任务，以真实的智能合约安全审计报告作为数据源，引入软件安全领域的公认标准——通用缺陷枚举（CWE）体系，通过分层架构全面覆盖各类软件缺陷，**为自动化构建统一、可持续演进的漏洞数据集提供了理想解决方案。**  
## 核心挑战  
  
将LLM应用于审计报告的自动化分析和CWE标注时，主要存在**三方面挑战**  
：  
  
首先，专业审计报告具有**内容复杂、篇幅冗长**  
的特点。以Trail-of-Bits 团队所审计的Uniswap v4项目的审计报告为例，长达**63页**  
的文档中既包含关键的漏洞信息，又混杂大量法律声明、测试方法、项目结构等非结构化内容，这对信息提取的准确性和效率提出严峻考验。  
  
其次，CWE体系本身包含**900余种缺陷类型**  
，形成复杂的**多层级树状结构**  
。传统关键词匹配等方法难以实现漏洞到CWE节点的精准映射。  
  
最后，LLM的固有问题也不容忽视。模型通常**上下文窗口长度有限**  
，处理长文本时易出现"Lost in the Middle  
"现象，即模型在长文本中间部分的召回能力显著下降，而模型的**幻觉**  
倾向则可能引入分类偏差，直接影响数据集的准确性。  
## 方法 - FORGE框架  
  
![FORGE框架结构示意图](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56uy9vr738ky7P5bRd2HibeeUBoHgd9v9PaDJHmlLj4CQ7uiaVpr5BsibUxA/640?wx_fmt=png&from=appmsg "")  
  
FORGE框架结构示意图  
  
针对上述挑战，我们提出FORGE框架——首个面向智能合约漏洞数据集构建的端到端自动化解决方案。该框架通过四大核心模块实现高效处理：  
  
**语义分块器**  
首先对PDF等格式的审计报告进行智能解析，依据标题、段落等语义边界将长文档分割为符合LLM处理长度的自包含文本块。这种预处理既保留了上下文完整性，又最大限度的满足了模型的输入限制。  
  
**MapReduce提取器**  
采用分布式处理思想。在Map阶段并行提取各文本块中的项目元数据（GitHub仓库、Commit ID、链上地址等）和漏洞相关的核心特征（漏洞标题、描述、严重性级别等）；Reduce阶段则通过信息聚合与去重，生成结构化的JSON输出。这种设计显著提升了处理效率。  
  
![ToT 方法驱动的分层分类器示意图](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56ueGsib8bfo7Jnc4SoIHtiaU5P3Qgo52XKyRFa2voMNdFicslp68wkY3aww/640?wx_fmt=png&from=appmsg "")  
  
ToT 方法驱动的分层分类器示意图  
  
**分层分类器**  
引入了思维树（Tree of Thoughts, ToT）推理机制。模型在CWE层级中逐层导航，结合上下文学习能力，动态选择最优分类路径。特别设计的回退机制确保即使无法定位到叶子节点，也能返回最接近的父级类别，极大提高了分类可靠性。  
  
最后的**代码获取器**  
基于提取的元数据，自动从GitHub、对应链区块浏览器拉取对应被审计版本的合约源码，与分类结果整合形成完整数据集条目。  
  
整个FORGE框架的流程实现了从非结构化的原始审计报告文档到结构化数据集的全自动化转换，大幅度降低了人工成本，提高了构建效率和一致性。  
## 评估  
  
在评估阶段，我们通过四个关键研究问题（RQ s）来全面评估FORGE框架的性能和实用价值：  
### RQ1: FORGE框架的数据集构建能力  
  
为了评估 FORGE框架的数据集构建能力，研究团队收集了由Etherscan平台验证的47个知名安全审计团队提供的6,454份有效审计报告作为原始数据。实验结果显示，FORGE框架完成全部报告处理共耗时229.5小时，单份报告平均处理时间为127.8秒，其中漏洞信息提取和分类分别耗时45.0秒和18.3秒。最终构建的数据集包含81,390个Solidity文件和27,497个漏洞记录，涵盖296个CWE类别。  
  
![FORGE 数据集规模统计](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56uGOicCQd1YBp3aqe6drK29od9libMib7j9uiczCd1B2dutYfBjVJPia2jnSA/640?wx_fmt=png&from=appmsg "")  
  
FORGE 数据集规模统计  
  
与现有数据集相比，FORGE构建的数据集展现出显著优势：项目平均代码量达2,575行，远超SmartBugs数据集的204行；采用最新Solidity编译器版本(v0.8+)的项目占比59.0%，而SmartBugs中90%以上仍使用过时的0.4版本。相较于人工标注的DAppSCAN数据集，本数据集在文件数量和漏洞记录方面分别提升了一倍和17倍，更好地反映了实际开发中的代码特征。  
### RQ2: 漏洞信息提取精度评估  
  
采用基于置信区间的随机采样方法，设置95%置信水平和10%置信区间，从数据集中随机选取96个样本进行人工验证。评估结果显示，FORGE提取不同信息类别的平均精确率达到95.6%，平均 Macro-F1分数为86.1%，证明其提取结果具有高度可靠性。  
### RQ3: CWE分类一致性评估  
  
考虑到漏洞分类的主观性——即使专业安全审计师也可能对同一漏洞有不同分类判断，研究采用了Krippendorff's   
  
 多标注者间一致性系数来衡量FORGE 的 CWE 分类结果与人类专家之间的一致性，同样采用96个随机样本，由两名人类专家独立分析每个漏洞的描述和代码，将其映射到最合适的 CWE 类别。评估结果显示，FORGE 获得了0.87的Krippendorff's   
  
 系数，高于建议的0.80高可靠性阈值。这一结果表明，LLM 驱动的自动分类方法在智能合约漏洞的 CWE 分类任务中达到了与人类专家高度一致的水平。  
### RQ4: 数据集使用价值验证  
  
实用价值验证（RQ4）中，我们对13款主流检测工具进行评估，涵盖静态分析、符号执行等不同技术路线。基于SmartBugs-Wiki的漏洞映射指导，将各工具能检测的漏洞类型映射到CWE类别。利用所构建数据集的真实漏洞进行的评估表明，这些工具的最高F1分数仅为18.59%，平均分数低至5.06%，部分工具甚至无法识别任何真实漏洞，这些发现不仅证实了FORGE 数据集的作为 Benchmark 的实用价值，更暴露出当前检测技术面对真实漏洞时的严重不足。  
  
![13 种工具的评估结果展示](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56uNB07lNiaLEzknNyWK5uYWfhzemlkPvb76Mn0mrqUF1hdOItkOqo543Q/640?wx_fmt=png&from=appmsg "")  
  
13 种工具的评估结果展示  
## 研究发现  
  
![CWE视角下的智能合约安全风险优先级示意图，每个矩形的面积代表该漏洞的出现频率，而颜色深浅则对应严重程度（颜色越深表示严重性越高）。](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56unYtON7kaJBqSWibPa2vY7dx5kCTGc9oicDtqiakgRX96nPOrXxaJYt7xg/640?wx_fmt=png&from=appmsg "")  
  
CWE视角下的智能合约安全风险优先级示意图，每个矩形的面积代表该漏洞的出现频率，而颜色深浅则对应严重程度（颜色越深表示严重性越高）。  
  
通过融合漏洞频率与CVSS v4.0严重性评分，我们基于FORGE数据集对智能合约风险进行了可视化，结果如上图所示，并通过多维度分析揭示智能合约安全风险的几个重要特征：  
### 风险分布呈现显著的非对称性  
  
从图中可以发现，编码规范类问题（如CWE-710）虽频繁出现但实际威胁较低，主要影响代码可维护性；而算术异常（如CWE-369）等低频漏洞一旦发生却可能造成严重损失。特别值得注意的是，访问控制缺陷（CWE-284）被确认为最严重的威胁类型，可能导致未授权资金转移等严重后果。  
### 研究还发现学术关注点与实际风险存在明显偏差  
  
![FORGE 数据集中的 CVSS 评分 Top10 与过往学术研究中的优先级 Top10 对比](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56uf5Tz13xtE9zrChKUwGkMoA56y7xMEMkd9KMyrNNdloXu8ibvNkgW8fQ/640?wx_fmt=png&from=appmsg "")  
  
FORGE 数据集中的 CVSS 评分 Top10 与过往学术研究中的优先级 Top10 对比  
  
对比Web3Bugs 工作所调研的37个顶级会议论文发现，学术界重点关注重入攻击（28个研究）、整数漏洞（16个研究）等问题，而实际审计平均风险级别更高的通信信道安全验证（CWE-940）和加密签名问题（CWE-347）却较少受到关注。  
  
这种差异可能源于两方面：其一是研究者倾向选择技术上更易检测的漏洞类型，其二是现有漏洞分析方法和工具难以处理需要复杂语义理解的业务逻辑漏洞。  
### 与传统软件漏洞相比，智能合约漏洞展现出独特的风险特征  
  
FORGE 数据集将智能合约漏洞映射到 CWE 类型，使得本文能够通过统一的 CWE 视角看待智能合约漏洞与传统软件漏洞分布上的差异。  
  
![FORGE Top10 对比 Owasp Top10](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WFXlk7qc1QyVgWVmxprI56unEVhpF4RpOBc6uXL3WZd0LuHxzBd1qia0ibic1cWShYvn5N0RmFibuuibLw/640?wx_fmt=png&from=appmsg "")  
  
FORGE Top10 对比 Owasp Top10  
  
与OWASP Top 10的对比分析表明，算术问题、重入攻击等级别较高风险在传统Web应用安全框架中并无对应类别，直接源于区块链技术特性。由于智能合约的金融属性，某些传统软件中影响有限的漏洞可能造成更严重后果。同时，传统软件的某些安全模式（如A10: Server-Side Request Forgery  
）在去中心化环境中失去意义，而新的威胁模式（如价格操纵攻击、跨链桥攻击）更受合约审计过程中关注。  
  
这些差异表明，智能合约安全不能简单照搬传统软件安全的防护策略，需要建立专门的安全框架、工具链和最佳实践。从风险评估、威胁建模到安全审计，都需要针对智能合约的特殊性质重新设计。  
## 结语  
  
FORGE框架通过分而治之思想的MapReduce框架与Tree-of-thoughts推理方案驱动LLM全自动地从真实的智能合约安全审计报告中提取漏洞数据并进行 CWE 类别标注，以95.6%的提取精度和0.87的分类一致性构建了包含2.7万漏洞的数据集，成功打破了传统人工方式标注数据集的瓶颈。基于该大规模数据集的实证分析则揭示了智能合约安全领域的多个重要洞察：学术研究与实际威胁之间的关注偏差、智能合约安全相对于传统软件安全的独特性、以及当前检测工具面对真实漏洞时的严重不足。  
## 作者团队介绍  
- 论文第一作者为**陈嘉弛**  
，中山大学副教授，博士生导师，主要研究方向包括
```
软件可靠性、智能合约安全、Web3安全、大模型技术及应用
```

  
等。近5年在
```
ICSE、FSE、ASE、ISSTA、TSE、TOSEM
```

  
等软件工程领域高量会议和期刊上共发表论文五十余篇，四十余篇为CCF A类论文。曾获得
```
 5 次 ACM SIGSOFT Distinguished Paper Award
```

  
，3次会议最佳论文奖，包括 CCF A 类会议 ICSE，ISSTA, INFOCOM等。  
  
- 论文其他作者为申一鸣（中山大学）、张家硕（北京大学）、李子豪（香港理工大学）、John Grundy（蒙纳士大学）、卲震哲（中山大学）、王焱林（中山大学）、王嘉水（浙江大学）、陈厅（电子科技大学）、郑子彬（中山大学）。  
  
  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
   
  
有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
**专题最新征文**  
- [期刊征文 | 暗网抑制前沿进展](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491610&idx=1&sn=8b6c9caf92435cbd9b76b77686619972&scene=21#wechat_redirect)  
 (中文核心)  
  
- [期刊征文 | 网络攻击分析与研判](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491661&idx=1&sn=ab0a97741cdf854757ef3024b03f1d44&scene=21#wechat_redirect)  
   
(CCF T2)  
  
- [期刊征文 | 域名安全评估与风险预警](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491703&idx=1&sn=7f351031fc81e1b63d5215ddb8dc91b5&scene=21#wechat_redirect)  
   
(CCF T2)  
  
