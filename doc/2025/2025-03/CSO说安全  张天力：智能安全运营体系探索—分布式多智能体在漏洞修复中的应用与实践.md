#  CSO说安全 | 张天力：智能安全运营体系探索—分布式多智能体在漏洞修复中的应用与实践   
原创 张天力  安在   2025-03-18 18:30  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/5eH7xATwT3icpLmjpDSQkXx16oAygiaJncke0vYYJvIkuzECibrQJcUW4oAedTuib1G9m372rleJRDNXNs54fBEVicg/640?wx_fmt=gif&from=appmsg "")  
  
由安在新媒体联合中国网络安全审查认证和市场监管大数据中心（CCRC）共同举办的第五届“超级CSO研修班”现已圆满结营。在导师引领和课程启发下，学员们均完成极具代表性的毕业论文，是各自相关领域网络安全建设、实践与思考的精华之作。  
  
  
本着分享交流之精神，我们特别精选几篇，以连载的方式呈现公众。希望借“CSO说安全”，让更多CSO们关注、支持并参与到CSO文化的沉淀积累和广泛传播中来。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/5eH7xATwT3icd5glIibuQ7WCicoicTZklXqmyRZppB1x5j6r6tQRAZeSicVA97H2zqo0suu2lzibMhqJRw5ibv97dnFgA/640?wx_fmt=gif&from=appmsg "")  
  
  
  
![未标题-1.png](https://mmbiz.qpic.cn/mmbiz_png/5eH7xATwT39tt72WLZ5Kh7qe8JKILM2iaicqd7pDqTNbmu9npR3Z2DasOaQjgWRNfpJqAFSJbpibKQkwZNkkZD7Vw/640?wx_fmt=png&from=appmsg "")  
  
**张天力**  
  
**某医疗科技**  
  
**安全运营经理**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/5eH7xATwT3icd5glIibuQ7WCicoicTZklXqmyRZppB1x5j6r6tQRAZeSicVA97H2zqo0suu2lzibMhqJRw5ibv97dnFgA/640?wx_fmt=gif&from=appmsg "")  
  
  
**摘 要**  
  
  
随着数字化转型的不断深入，企业在面对网络安全威胁时，除了需要实时防护外，更需在漏洞修复环节迅速响应并保障业务连续性。然而，传统的漏洞修复流程往往存在知识覆盖面广、人力依赖度高、操作成本大等问题，导致许多企业在实际运营中面临漏洞积压、风险不可控等难题。为此，不少组织开始探索将人工智能（AI）技术融入安全运营体系中，期望以更低成本和更高效率来应对复杂的安全挑战。  
  
  
为了化解这些难题，越来越多的企业开始在安全运营流程中引入自动化与智能化技术。然而，大多数解决方案基于现有基座模型结合安全全领域语料训练一个安全全领域的模型，从而尝试进行安全提效，但在实际使用中由于安全领域的复杂性，这种AI 性价比较低，难以产生价值。  
  
  
在此背景下，本文提出一种“分布式多安全智能体-DMSIA（Distributed Multi - Secure Intelligent Agents）”的安全运营体系构想，并以漏洞修复为例进行实践探索。不同于传统的“大而全”统一 AI 模型，本方案将安全运营流程拆分为更细的子任务，分别交由专门的智能体节点处理从而构造“分布式多安全智能体安全运营体系”。通过合理的调度与知识检索手段，各节点既相对独立，又能协同配合，从而降低安全团队在多系统与多层级场景下的实施成本，提升整体安全运营成效。  
  
**关键字：**  
安全运营，智能体，降本增效  
  
  
**0****1**  
  
  
**引言**  
  
  
**1.1 研究背景与痛点**  
  
  
  
**1.1.1 多样化系统带来的复杂性**  
  
在现代企业环境中，Windows、Linux、macOS、网络设备、云原生容器等往往同时存在，且每类系统的漏洞修复方式、补丁发布渠道都有所差异。以人工方式“扫遍”所有平台，不仅效率低，还容易出错。  
  
**1.1.2 传统大模型方案的局限**  
  
早期尝试在安全领域内直接应用通用大语言模型（LLM）时，普遍面临以下问题：  
  
●知识库过于庞大：混合了不同操作系统和安全文档后，检索和推理效率明显下降；  
  
●更新维护难度：安全事件和漏洞信息需要及时更新，大模型一旦离线训练后就难以快速迭代；  
  
●幻觉风险：当模型面对大量专业内容容易出现“编造”式的错误信息，导致修复建议失准。  
  
**1.1.3  传统大模型方案的局限**  
  
不少安全团队希望通过自动化编排工具、智能化技术实现降本增效，但又担心高昂的硬件与服务成本（如GPU集群、大规模模型训练等）。因此，能够在现有基础上叠加的“轻量”且“可扩展”方案，更易被中小型企业或预算有限的组织所接受。  
  
  
**0****2**  
  
  
**“分布式多智能体”在安全运营中的概念**  
  
  
**2.1  多智能体的内涵**  
  
  
  
“多智能体”思路源自人工智能与软件工程领域，强调将复杂任务切割为多个更小的、相对独立的模块（Agent），每个 Agent 针对特定的知识域或功能进行精细化处理。  
  
●独立性：每个智能体拥有自己的知识库或专用算法；  
  
●协同性：在可视化工作流或消息总线的驱动下，各智能体可以共享中间结果或触发后续动作。  
  
  
**2.2 分布式的意义**  
  
  
  
“分布式”并不一定指完全去中心化，而是指在架构上允许每个节点独立部署或执行，再通过统一的编排层进行调度。这样做既能提升系统弹性，也能让企业根据自身需求选择在私有云、公共云或混合云中搭建这些节点，从而控制整体成本。  
  
  
**2.3 对漏洞修复的适配性**  
  
  
  
漏洞修复流程包含“分析—排查—修复—验证”多个阶段，不同操作系统的修复方式也各异。多智能体模式有助于在每个子环节切换到最合适的“专精”节点，从而在不大幅改变企业现有安全工具链的前提下，实现高效率与高准确度。  
  
  
**0****3**  
  
  
**分布式多智能体的部署与实践案例**  
  
  
**3.1  分布式多智能体的部署与实践**  
  
  
  
为了将多智能体构想付诸实践，本文选择了以下三类关键组件，通过这些组件并以“分布式”形式灵活组合，从而达成分布式多智能体的实现。  
  
**3.1.1  工作流与流程编排**  
  
所使用如n8n等可视化工作流工具，将漏洞发现、情报收集、资产排查、修复执行、复测报告等环节串联成有机流水线。每个环节通过不同智能体节点完成。  
  
●优点：降低集成难度，灵活编排，易于条件判断（如当严重度高时通知人工审批）。  
  
●低成本性：n8n可在普通服务器或Docker容器上运行，无需昂贵硬件。  
  
**3.1.2  定制各节点AI**  
  
使用Dify 平台举例，企业可以灵活地通过dify定制所需的 AI 智能体，使智能体实现各个场景的特殊功能，包括不限于数据库读取、调用外部接口或执行其他特定行为等。这种高度定制化的能力使得每个智能体能够根据具体任务的需求，灵活调整其功能，从而更精准地处理漏洞修复、资产排查等不同环节。与传统的统一模型不同，Dify 允许智能体根据不同的操作环境和需求动态适配，大大提升了修复过程的效率和灵活性。  
  
**3.1.3  增强型知识检索RAG（Retrieval-Augmented Generation）**  
  
通过RAG（Retrieval-Augmented Generation）来实现各智能体独立的本地增强知识库，知识库中不仅放入贴合公司业务场景的语料外（IP规律，系统架构等）。并且每个智能体仅使用与其节点职责相关的知识，避免了信息的过度扩展。提升任务执行的准确性，并减少智能体的训练难度。因为它允许每个节点在处理任务时，只检索和使用基于这个智能体职责的相关领域知识，确保智能体能够高效且精确地完成任务。  
  
  
**3.2  应用案例：基于分布式多智能体的漏洞修复流程**  
  
  
  
Log4j 是一个广泛使用的 Java 日志库，在 2021 年末，Log4j 2.x 中爆发了一个严重的 RCE（远程代码执行）漏洞，CVE-2021-44228，广泛影响了多个行业和服务。这一漏洞允许攻击者通过特制的日志消息触发远程代码执行，导致严重的安全问题，特别是云服务和应用系统中可能存在易受攻击的组件。  
  
在这一场景中，本文将展示如何利用分布式多智能体模型，以低成本的方式防御这一 0day 漏洞，并实现自动化修复。  
  
**3.2.1  资产排查节点**  
  
对 Log4j RCE 漏洞进行初步分析后，根据漏洞分析结果，识别和筛选出企业内部可能受影响的资产。  
  
资产排查智能体根据分析的影响版本信息，根据dify配置的相应接口与本地RAG知识库中的企业资产知识与主机资产知识，调用企业 CMDB 或 HIDS，列出所有运行受影响版本 Log4j 的服务器、服务和应用。  
  
**3.2.2  资产修复节点**  
  
资产排查智能体根据分析的影响版本信息，根据dify配置的相应接口与本地RAG知识库中的企业资产知识与主机资产知识，调用企业 CMDB 或 HIDS，列出所有运行受影响版本 Log4j 的服务器、服务和应用。  
  
以此漏洞为例，可分为Linux 修复节点 或 Windows 服务修复节点 ，针对不同的资产，分别采取特定的修复措施。修复节点将资产按操作系统类型（如 Ubuntu、CentOS、Windows）和应用类型（如 Java Web、API 服务等）进行分组，分别加载对应的修复建议。  
  
以java修复智能体举例，根据RAG库中的修复知识，结合dify的特定编排进行下列操作从而进行自动执行－调用企业内部安全/运维操作统一下发平台自动植入，虚拟补丁（javaagent疫苗热加载/RASP热补丁）  
  
**3.2.3  验证与报告节点**  
  
验证与报告节点 在修复完成后，负责验证漏洞是否已被有效修复，并生成修复报告。  
  
验证方法：修复节点通过 n8n 调用“验证与报告节点”，对受影响的系统进行漏洞复测。通过执行已知的恶意测试（如构造恶意 JNDI 字符串进行模拟攻击），确认漏洞是否已完全修复。  
  
若验证成功，说明漏洞已经修复，系统可以安全运行。  
  
若复测失败，验证节点会要求回滚到上一智能体并重新执行修复步骤。  
  
报告生成：当验证通过后，报告节点会根据修复过程中的信息自动生成报告。  
  
  
**0****4**  
  
  
**“分布式多智能体”的优势与挑战**  
  
  
**4.1 “分布式多智能体”的优势**  
  
  
  
**4.1.1  更高精度**  
  
专用的知识库结合相应的 AI 节点，减少“杂乱”知识引发的混淆。  
  
**4.1.2  灵活扩展**  
  
企业可根据需求增设节点或知识库（如容器修复、网络设备修复），无需推翻全部架构。  
  
**4.1.3  成本可控**  
  
无需大型 GPU 集群训练统一模型，分布式节点可利用普通服务器部署或云端服务，部署门槛相对较低。   
  
  
**4.2 “分布式多智能体”的挑战**  
  
  
  
**4.2.1  知识库维护**  
  
由于架构问题，导致节点对于知识库有着强依赖性，需持续更新各个智能体节点知识信息，内部接口变动必须及时更新，否则 AI 节点的准确度会随时间下降甚至出现执行失败  
  
**4.2.2  分布式节点的流程设计与节点设计**  
  
多节点协同需良好的工作流编排与异常处理机制，过度复杂可能增加人工对系统额外的维护负担。同时如果节点设计存在问题，可能会引发误报甚至误操作问题。  
  
  
**0****5**  
  
  
**“分布式多智能体”的展望**  
  
  
在目前降本增效的大环境背景下，通过将漏洞修复流程拆分为多个子任务，并在每个子任务中配置专用的智能节点协同，企业得以以较低成本实现安全运营效能的显著提升。与传统“大一统”模型相比，“分布式多智能体”在精度、灵活度与可扩展性上都有明显优势，尤其适合多操作系统并存、缺乏大规模训练资源与降本增效的甲方公司。 未来，随着云原生、边缘计算与物联网（IoT）的兴起，安全运营将更加去中心化、实时化。多智能体的理念在威胁情报共享、跨环境安全策略协同、自动化应急响应等方面，都有更广阔的应用空间。通过进一步探索节点之间的自学习与共享机制，或采用更完善的知识图谱来提升检索与推理效率，从而构建真正的“下一代智能化安全运营体系”。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/5eH7xATwT3icd5glIibuQ7WCicoicTZklXqmyRZppB1x5j6r6tQRAZeSicVA97H2zqo0suu2lzibMhqJRw5ibv97dnFgA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
**往期学员感想：**  
  
  
****“虽然课程内容并不意外，但导师们所分享的先进职业经验，却有着不可估量的价值。在我们具体开展工作、将想法落地实施之前，这些经验能够提前为我们提供最佳实践方案，还能贴心地提醒我们在工作过程中可能会遇到的各种‘坑’，避免我们走弯路，这无疑是课程中极为关键的部分。”  
  
详情参学联系：  
  
**徐青青（xuqingqing823125689）**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/5eH7xATwT39TwSy7P37zyImD2CrGpbueOwJdV4AVazgDukvrdEdficrnLGZ3bWbiawNBp678jbfXJwBGgribgN5kA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
   扫码联系  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/5eH7xATwT38ltaZPBACjQRsSQcA7UziaZDxACmQItcsbnVn8U4OOgqV1hX2Jt7bf7nFhQ1ibpIXSGRSMsnqWAfrA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
同时欢迎来自各界的赞助合作，合作方式包括品牌赞助、参学赞助、酒会赞助、活动赞助等多种形式，有意请速洽：  
**徐倩（Madeline_Sue）**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/5eH7xATwT39TwSy7P37zyImD2CrGpbuewwhgialSn0oqYXicNibPdJQGqlbus3MicJaxFrlNh5ibwxLEBMH5Qdh8U1Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
   扫码联系  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/5eH7xATwT38ltaZPBACjQRsSQcA7UziaZDxACmQItcsbnVn8U4OOgqV1hX2Jt7bf7nFhQ1ibpIXSGRSMsnqWAfrA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**第五届超级CSO研修班全貌**  
  
**过程回顾**  
  
[启动](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247624678&idx=1&sn=164a1125dab8f226cb14d04ad2dee3de&chksm=feb28d26c9c50430e951c8703ad0517d58a1b2f427ed5851c8c9b618277d570bcb44775dcf5e&token=1228889044&lang=zh_CN&scene=21#wechat_redirect)  
  
   
  [线上播课 ](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247625777&idx=1&sn=74c81140dc0f035f01ad09959748233a&chksm=feb286f1c9c50fe73adf541a7029b0627b2ead66b9dc491a275f04b32e06364ef0b8b0da0f1d&token=1228889044&lang=zh_CN&scene=21#wechat_redirect)  
 [导师](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247627041&idx=1&sn=f49f82884960b92e1401b4ff5a24515d&chksm=feb29be1c9c512f73c58330172cfb5a0fc357ed4cf93e82d5f95e851d7cc90aaa173655aa5ee&token=589245978&lang=zh_CN&scene=21#wechat_redirect)  
 [开营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247631240&idx=1&sn=e5cf252a1c92669000a973f8a6113803&token=987344682&lang=zh_CN&scene=21#wechat_redirect)  
 [结营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247636719&idx=1&sn=98e24c3872eb5d5b71af11c293a00ca0&scene=21#wechat_redirect)  
  
  
  
**导师授课**  
  
  [陈建](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247634697&idx=1&sn=3c90623ca8d190c46f711da5229b95d0&scene=21#wechat_redirect)  
  
  [鲁京辉](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247634311&idx=1&sn=733180a62dadbd4407bbeb218c844511&scene=21#wechat_redirect)  
  
  [杨哲](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247635885&idx=1&sn=b698edb1121bedf06fba16f179b3eafb&token=584909505&lang=zh_CN&scene=21#wechat_redirect)  
  
 [陈洋](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247635977&idx=1&sn=c969e1accbe54366d828f026ffbeeac1&token=147285742&lang=zh_CN&scene=21#wechat_redirect)  
  
 [杜跃进](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247636358&idx=1&sn=87ce38dc5d636b8975a99ca7305f711d&scene=21#wechat_redirect)  
  
 [谭晓生](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247636784&idx=1&sn=608f8bb6d931ec95f307d7055385d3ed&scene=21#wechat_redirect)  
  
  
  
**学员论文**  
  
  
[曹静](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247637006&idx=2&sn=bf2a2076103b3522bdb60ee0310710c0&scene=21#wechat_redirect)  
 [李国](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247637077&idx=2&sn=b93785741ef325f6611f08135d6076a6&scene=21#wechat_redirect)  
  
 [潘安磊](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247637372&idx=2&sn=1514db2365728d2a01935bff15593509&scene=21#wechat_redirect)  
 [裴新](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247637425&idx=2&sn=3e29b078af134e36a685e4704212c642&scene=21#wechat_redirect)  
  
 [杨明](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247637509&idx=2&sn=766a15bc945be64e09fa2c8a04a5738a&scene=21#wechat_redirect)  
  
  
  
**第四届超级CSO研修班全貌**  
  
**过程回顾**  
  
[启动](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247593168&idx=1&sn=3fe00c910c0a43e3e7925f6af4af5a04&chksm=febd0610c9ca8f065a69ee72db6af761f50cbb4b49234eb33aa34d3a197072ed43239247e7a1&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
   [导师](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247595516&idx=1&sn=07d77d93c1218983eb20059f0c38c037&chksm=febd1f3cc9ca962a2573f27fd874b40193bfaecaa9bfd7f3d81320754387c0052f8a48656fe0&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
   [开营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247601599&idx=1&sn=6a64163d1a97587914d7f475470c527e&chksm=febd277fc9caae692efd012b6e12a12f243f434c84c29741751cc223ab7c16530b7bdc5769d3&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [ 结营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247611954&idx=1&sn=3a4a676a049c961beae8534662accdf4&chksm=febd5cf2c9cad5e458254d9b7fb825d0341ff0c0ac33ca9cb8a97c693a2d42fb16e132c3c5d7&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
**导师授课**  
  
  [陈建](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247604436&idx=1&sn=7b4b101cace0d1ee12e518b8bdcfc4ff&chksm=febd3214c9cabb02c1ff88d82ab69443de13395dfc859bf858e1bb85996ac4a72318fcae4129&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  [毕马宁](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247603826&idx=1&sn=54d4c6310b45ce611f060da7630e250b&chksm=febd3cb2c9cab5a4f01007c1862bc1881729ff7af1c39e238c3e69f4f8ccb43dd4520ea0848b&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  [谭晓生 ](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247602594&idx=1&sn=d81cf742c569e15d40957dabc98b9241&chksm=febd3b62c9cab274824609bda43ab3986193869379d85266e0994b4c2266e64c825b7acf5af2&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
 [杜跃进](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247608277&idx=1&sn=20a0fef7e9bc4a99e716b1f869b3701c&chksm=febd4d15c9cac40356fabe88ab070ac1f27bd317b79a577593bd8367af3bf6f5bff0c0676639&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  [张照龙](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247610748&idx=1&sn=5f12cde35eaa1e7ca8094c3275fc6fea&chksm=febd5bbcc9cad2aa6db62771c30e906ff8c7a4a65c482018ef2c7a8c703e21dce9992321bdc9&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  [贺嘉](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247611138&idx=1&sn=fa72f2632adf3a940a03d5e5476c3d5f&chksm=febd59c2c9cad0d4f4533e132d6e4a6d58606b307152dca89fcff07015570777106f2f6ad9d1&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
    
  
[刘新凯](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247607101&idx=1&sn=f8f097face43a497390eafbd1d57d1e8&chksm=febd49fdc9cac0eb82218c9fdd4f52827ee9d7d8c5e5d9f41dd6434dd155c8b961dad3066e53&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [赵明明 ](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247610284&idx=1&sn=692afa056d3755d942616a0ee666783d&chksm=febd456cc9cacc7ac1be8d3412cf7f50d936e07722fff0396ddd97f7f460c7bd880a093f20a1&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
[陈洋](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247609887&idx=1&sn=c10a9706f0545b69ecebd4d261354f28&chksm=febd44dfc9cacdc9974bc13ae01974a6f0208d12ce13bb668364b15099a13680e2f8b88f08f6&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [周智坚](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247606301&idx=1&sn=de027ab3ce7983ced58cb3dd79c524d0&chksm=febd4addc9cac3cbab74165a6ba022ccead86cf5d867f601711bce66cde3e1e39ca2805fcd2c&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [陈雪频](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247605208&idx=1&sn=514f241e9b1642cb1d42f86dfbe80a48&chksm=febd3118c9cab80efe919bab7986c5162049738e30f3173118558b4577f741c425fd58107597&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [欧阳梅雯](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247603075&idx=1&sn=003274761e9ac4c24e750ef16e62619b&chksm=febd3943c9cab055ca777979b0188a89f14116e8a49157c0167d59de59399b9a8e7cfd1b81fd&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
**学员论文**  
  
  
[杨文斌](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247612543&idx=2&sn=a18f2b9ff3f7825d7a71f205d43f1e9d&chksm=febd52bfc9cadba92b42fb0c720104b268c21884248c9c6b507bd2854624a07d9fc11abc5550&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
 [高飞](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247612666&idx=2&sn=cd179d4d4862b47f0bc52ba9af123560&chksm=febd523ac9cadb2cddc5b33204dce2a2ffc28ed098a0fcb6c65a32ceec18b140f42d2bf70da2&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
 [方静怡](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247612900&idx=2&sn=61032c8a972cb42e13dd398657abfcdd&chksm=febd5324c9cada326ee9d673c064a9f6c8dee8ed321619f6c6949f3b39666aa15f49a9936f82&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
 [李鹏](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247613293&idx=2&sn=baa2d6a669a162364af873f8fddcb59b&chksm=febd51adc9cad8bbd831b040ae96cf61986b9e69602ea75a30a07f65d63867c2974299b598cc&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
 [王明博](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247614250&idx=2&sn=9f8ef45d352a1f72ded66a8db8cd8a75&chksm=febd55eac9cadcfc4fddbfd7628583b439785cf50dee0549b1105588552ceb1370faf6f32aeb&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
   
  
[鞠叶 ](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247616069&idx=2&sn=2a0db1bd3daafd6acbbbdc8508fd7c55&chksm=febd6c85c9cae593f32f0e03b89c59a946e20ecb3284b563be790d1e397de009f0c22b2065cf&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
[董永乐](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591984&idx=3&sn=3b6b27c2a4cfc037c8050e2017c143e0&chksm=febd02f0c9ca8be6b239205220800b442c226d44120ae4471f68c0ba33677b31f14133de774d&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
 [赵传庆](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247615976&idx=2&sn=fd2aab6fb80a221e2450469136a6cd2f&chksm=febd6f28c9cae63e57294710ba2b2ed2f259c17482ed29a583ecc3366ac1f4db712ebf28d655&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
 [陈龚旖](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247616425&idx=2&sn=e391a90fb9ccea7b2f602c37f646f5fb&chksm=febd6d69c9cae47f1b29a6d42367e9d8c366ed4dd0ef9415b9a04763347f1b36d1f15fd06838&token=1948869975&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
**第三届超级CSO研修班全貌**  
  
**过程回顾**  
  
[启动](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247559567&idx=1&sn=87fa57629c9ed8ad995578b586c8b60d&scene=21#wechat_redirect)  
  
   [导师](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247561386&idx=1&sn=9c6e753138744636263ecaf498c6dec2&chksm=febd9a6ac9ca137c79700681cca6efcdb02c60b8357cde7c6bb4b56893f3831028b4c32a96f7&token=1855342484&lang=zh_CN&scene=21#wechat_redirect)  
  
   [开营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247577502&idx=1&sn=6dcae7457a712836cb465aa74d301217&scene=21#wechat_redirect)  
  [结营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247588572&idx=1&sn=1378448eca758508e06d07f23021fdbd&chksm=febdf01cc9ca790a01cfcd8a25f4bf8f15f3a337638faa18c109759495b59f76d445e6c52bff&token=1284185725&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
**导师授课**  
  
[陈建](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247580684&idx=1&sn=560c89a374ffbe2fc0c953f53f69f63b&chksm=febdd6ccc9ca5fda5754f19d24b30a0c30bf7cace30197781c2a8b4d0223990148022609d17f&token=1526962627&lang=zh_CN&scene=21#wechat_redirect)  
  
  [毕马宁](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247581826&idx=1&sn=88aabcec56491c7e2cca369965e4389c&chksm=febdea42c9ca635476a0e42593497b50c0a7e0a709d82f2600c1aba14b019f1256a534950349&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
  [谭晓生](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247583029&idx=1&sn=8c2ec4f5689894696d4924158b9f6d9a&chksm=febdeff5c9ca66e3243a727076447abd86d532a2df5dd0b85d1e76524a67c8b650a004100b39&token=988780999&lang=zh_CN&scene=21#wechat_redirect)  
  
  [杜跃进](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247583663&idx=1&sn=1154f9ade2ade3fbdfcb6059a0d61197&chksm=febded6fc9ca647902f525c5ca2eb0a66ac6ec95cb1bb0cc4f507764f8b0a2e6ee1f5df65428&token=511858520&lang=zh_CN&scene=21#wechat_redirect)  
  
  [张照龙](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247585983&idx=1&sn=af0e268a657cdde1c9607fa0ee347d13&chksm=febdfa7fc9ca73693fb87626e33de595a935e9fb99e2102f981b4f66011f8221f3228be75ac4&token=1127921851&lang=zh_CN&scene=21#wechat_redirect)  
  
  [贺嘉](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247587090&idx=1&sn=9f4913eea3580ecd243f06361e03cade&chksm=febdffd2c9ca76c4437624880feb27924cf10c49a4baf212e987a35eea997c46561b19688672&token=75401260&lang=zh_CN&scene=21#wechat_redirect)  
   [刘新凯](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247592703&idx=1&sn=0cdab5046abc5a4e6f8a8693ec140c38&chksm=febd003fc9ca89290a6e5b85bbc153381d472263ccd92aa4e5cab540e4ffa7cfca07fcbf5de7&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
  
  
**学员论文**  
  
  
[王星骅](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247589243&idx=1&sn=040f5bc0b158923d71456020887b2a51&chksm=febdf7bbc9ca7eadf98e4501beb4db4e927cde8c8802101cbad9d2b8cad7936d93c1aa425fd4&token=867549261&lang=zh_CN&scene=21#wechat_redirect)  
  
 [ 李达](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247590283&idx=3&sn=9709ce841cea597eae8401424aa9d169&chksm=febd0b4bc9ca825dc51e6e02f4e2f1f388d56d28a25738dc536e73552a619161338a61a729d0&token=1171689749&lang=zh_CN&scene=21#wechat_redirect)  
  
 刘歆轶  [肖茂林](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591044&idx=3&sn=6bb40ff63792adab5febfafc3cf48a43&chksm=febd0e44c9ca8752a4e91143ce72c4df828bedaeb166826378d456b8e2554e35894dd4aac5e9&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
  [姚旭](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591302&idx=3&sn=b04a4c9ef6342d6efd5d96bc6cc768e1&chksm=febd0f46c9ca8650cae85b44cb5c69ebcc43707a5f18713d37b6865c17c0d580c21154eed143&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
    
  
[王利伟](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591425&idx=3&sn=8ed730015932831bf6fc3e0e2a9119bf&chksm=febd0cc1c9ca85d7e3b5a66a4525729a08eedf9f66b31bcd74fead5e31d8a87d70397cac41d6&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
  [徐俊超](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591546&idx=3&sn=d8bd06c9bd6abb04f7587a7a8d2f7675&chksm=febd0cbac9ca85ac599a6e5b662a437b08656ced0122550ea2414a1ee32dd411ef64bc7a5c11&token=753644910&lang=zh_CN&scene=21#wechat_redirect)  
  
  [李鑫](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591637&idx=3&sn=5059dd8133f5f84714d93236bedd47e8&chksm=febd0c15c9ca850331aec583be157d089ae9286ec5504007bb9ec5ec3ceae99116a5741cc1d5&token=691783484&lang=zh_CN&scene=21#wechat_redirect)  
  
  [董永乐](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247591984&idx=3&sn=3b6b27c2a4cfc037c8050e2017c143e0&chksm=febd02f0c9ca8be6b239205220800b442c226d44120ae4471f68c0ba33677b31f14133de774d&scene=21&cur_album_id=2515531519684444161#wechat_redirect)  
  
  
  
**第二届超级CSO研修班全貌**  
  
**过程回顾**  
  
[开营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247533953&idx=1&sn=822a0659d56aeb3c5f66563ca2e45cbf&scene=21#wechat_redirect)  
  [导师团](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247533944&idx=2&sn=310e1bab5a0ed829f3dcbf6ce32a5344&scene=21#wechat_redirect)  
[ 结营](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247537811&idx=1&sn=698fe6fef17e3d22133402ed56db296c&scene=21#wechat_redirect)  
  
   
  
**导师授课**  
  
[谭晓生](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247533966&idx=1&sn=6dab259479654d646bde350c32c7df69&scene=21#wechat_redirect)  
  
  [刘新凯](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247533978&idx=1&sn=cc760767cf59a8e0da17e1b1d229f185&scene=21#wechat_redirect)  
  
  [欧阳梅雯](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247534015&idx=1&sn=e0e12d9151114359932a1c223a62365f&scene=21#wechat_redirect)  
  
  [欧和](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247534043&idx=1&sn=61865bdb08dce0befb47b87718b629fe&scene=21#wechat_redirect)  
  
  [贺嘉](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247534046&idx=1&sn=56ad44afec79996c0782701d1e10433f&scene=21#wechat_redirect)  
  
    
# 吕一平  黄承  杜跃进  李吉慧  杨哲  
  
  
**学员论文**  
  
[丛林](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247546178&idx=2&sn=c23a25b921c9ed7edce273dcb6abb5f7&chksm=febc5f82c9cbd694fd0335fb49f2dc8055e37d8dbf4825703679bc1071d0dc7d50c0f65a0c87&token=214898153&lang=zh_CN&scene=21#wechat_redirect)  
  
  [张福明](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247546751&idx=2&sn=7cf79274f4e99090e505fa740a43d5fc&chksm=febc5dbfc9cbd4a9d8f73b5de1f3d56213cbdf66b2e9b14faa7fcd24a68175438c79d85e54b8&token=1805729390&lang=zh_CN&scene=21#wechat_redirect)  
  
  [宋士明](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247552556&idx=1&sn=b6cc9cc752b75fa6899d0db81ae2e424&chksm=febc64ecc9cbedfa3297474d119770e2e6b5dec112d4e8f96ceff1952e95527acb95e8144a0c&token=1766160733&lang=zh_CN&scene=21#wechat_redirect)  
  
  [冯斯恩](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247552726&idx=1&sn=481fd075d5ef3601b52166d0acfcb5c2&chksm=febc6416c9cbed002ebe95eff2007333283da759b878b94af929add7dba636c7f7deda56b361&token=1113999855&lang=zh_CN&scene=21#wechat_redirect)  
  
   
   
  
[王书魁](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247554021&idx=1&sn=cc2d19f2b1bbd640143b116011beccda&chksm=febc7925c9cbf033570fce9a475f9db892d1e4101a21a4594aa6372e5f06739e95814fb1ecbd&token=1284793759&lang=zh_CN&scene=21#wechat_redirect)  
  
  [徐越](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247555288&idx=1&sn=4c0218217be07b324c0ed8703cf52660&chksm=febc7218c9cbfb0eb648e25aca66068a8f4fd4bf72678c98ded1874bea18a05279b90d34c92a&token=2114742558&lang=zh_CN&scene=21#wechat_redirect)  
  [殷国祥](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247555163&idx=1&sn=c3f66fc8dd1ac460adcd0a5c250643a6&scene=21#wechat_redirect)  
  [乔庆鹏](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247556467&idx=1&sn=30f31421d69278c33650a4966bfc43b1&chksm=febc77b3c9cbfea5c9cae616aec571f8de00e4db068bf9b2e19c1cbf659bc16f1a993a486116&token=2114742558&lang=zh_CN&scene=21#wechat_redirect)  
  
  [沈勇](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247556595&idx=1&sn=76acda59f2f0809e429fe8ad2ff45efe&scene=21#wechat_redirect)  
  
    
  
[沈嗣贤](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247557861&idx=1&sn=1fb944afbf1f2e6307c3538a004a572f&chksm=febd8825c9ca013369a5902b37be01c773cd1cc72effdb211906c99b022852a35b58fcf68042&token=2125421464&lang=zh_CN&scene=21#wechat_redirect)  
  
  [肖波](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247558656&idx=1&sn=dced1a99614bb100a33793acba185599&scene=21#wechat_redirect)  
 [黄福胜](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247558780&idx=1&sn=01caa1d005731cf565ba2c2edb33197e&scene=21#wechat_redirect)  
  [王平](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247560094&idx=1&sn=b230b0cc5153dcabc078c3a582706475&chksm=febd815ec9ca08482fec5f2f838ba131b6ae1e78df9f2b0249702a2c3f4cb170380b6cc4f8bc&token=131757509&lang=zh_CN&scene=21#wechat_redirect)  
  
 [ 江洁文  陈圣](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247560254&idx=1&sn=7c324f89b4eb0b7f0050faf114a73b8d&chksm=febd86fec9ca0fe86e1e992a08c7ec345e2fe575b1ab8561099c06aa91560def9eaf69aa64b3&token=2125421464&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
**首届超级CSO研修班全貌**  
  
**过程回顾**  
  
[首发](http://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652891962&idx=1&sn=1a9b74e662b2b8fa7e83a77a2da200ad&chksm=f3410412c4368d042299e48592edcdf56244c100c991d3a18118e375dd77127dc65c99eb21f8&scene=21#wechat_redirect)  
 [CSO说](http://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652892339&idx=1&sn=c1278de4822a1e41d76ff617ce9882fd&chksm=f341039bc4368a8d024881674ccd4d62b887457f4eed7e007d81e196e520b719a71fa4596db5&scene=21#wechat_redirect)  
[ 报名](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652897603&idx=1&sn=ee1743ace1b659dd92f7aaed5f696052&scene=21#wechat_redirect)  
[ 导师团](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652898916&idx=1&sn=c45d8c64080f5de843da9f36a81957b6&chksm=f37ee94cc409605aea5a99beececadc52555229b95459317afaabf5c1d2932fe8a5460ed708d&token=1211718701&lang=zh_CN&scene=21#wechat_redirect)  
[ 领航](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652899365&idx=1&sn=19a6bab26fcf80456e739f40e371df27&scene=21#wechat_redirect)  
[ 价值](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652899674&idx=1&sn=60f668b6673debc28b4080fdbbc5a8a7&chksm=f37ee672c4096f64e3ba0c222f2abf7fcdae3cc6cc31b7864fc1e7d7f3b5438597d63f3dc34f&scene=21#wechat_redirect)  
[ 开营](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652902058&idx=2&sn=9e97c17110faeafce690458b74c39db1&chksm=f37efd82c40974946dc01baaf4493d28e1a9c2ab3a18f796541c653864d4c152bf4e86f3038e&scene=21#wechat_redirect)  
[ 揭幕](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652902352&idx=1&sn=ab39cbce834e7b68c885962ce5d9f586&chksm=f37efcf8c40975eed3b9e1023b434d0e4af23cc43e13a0849e441e40506a1bdad9b32443708a&scene=21#wechat_redirect)  
[ 结营](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652908443&idx=1&sn=ef31bbb0edebb80ad8b63ea8b0b2953c&chksm=f37ec4b3c4094da505e09dc5b030765e9368ff05f3eb4ef1f33543b05941503219f021bbdfd5&scene=21#wechat_redirect)  
  
   
  
**导师授课**  
  
[谭晓生 ](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652902639&idx=1&sn=5a363f4415d9087aea3bfe734b89368f&chksm=f37efbc7c40972d1cc5ecc90440641a476707f8465b36d4e0efaddaa2b982583f9c01f96f753&token=1761955986&lang=zh_CN&scene=21#wechat_redirect)  
[黄承 ](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652902968&idx=1&sn=420eb151720c3273216c26925c889568&chksm=f37ef910c40970069888234208df65ff14d0a598ffa8300652623bed1bcddbd21dbd9bbbf9f9&scene=21#wechat_redirect)  
[马民虎](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652903209&idx=1&sn=45f95c1e46f2bfba3136ca8b6b169016&chksm=f37ef801c4097117ad36ea44d5645713402c1752b71172d0d93a34236b2e6c38ad4fc351f398&token=945555121&lang=zh_CN&scene=21#wechat_redirect)  
  
   
[季昕华 ](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652903760&idx=1&sn=8b58b1701265605ec43662dcaff237ca&chksm=f37ef678c4097f6efdd150dc6b4fb9c7651973694ed69cbf427b5706f1f68c48b6eae802d00b&token=1002812973&lang=zh_CN&scene=21#wechat_redirect)  
[陈建](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652904148&idx=1&sn=69690012b480e697c2cdb6f3d4e86362&chksm=f37ef5fcc4097cea95dc80cb86681f8f6986ad73ecb529e9fdc1508bb315c534d148feb1ef75&scene=21#wechat_redirect)  
 [宋琳](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652904682&idx=1&sn=170dd217edde19e03aeadf736ccb8c31&chksm=f37ef3c2c4097ad4d2455f7a6c2f7153f269c2ccd9732f84e41b10faa2c900aa2d1cec428329&token=408792239&lang=zh_CN&scene=21#wechat_redirect)  
 [杜跃进](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652905428&idx=1&sn=b06f2014eb2a04dff3dbd9416962ed19&chksm=f37ef0fcc40979ea66a7162a23e2e1cd175ac7013800ce7ac52357344cadb10b0de97cd4d43e&token=1746597559&lang=zh_CN&scene=21#wechat_redirect)  
 [段海新](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652906116&idx=1&sn=5b12883c298e1c0b98a3fa9543776c83&chksm=f37ecdacc40944ba55c7f03fd6f02d879642299f80a754d19e676f50e97259996c70d2a135c6&scene=21#wechat_redirect)  
 [胡洪涛](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652906506&idx=1&sn=9336a97d59ad8f65ee02db80dd65bd25&chksm=f37ecb22c40942344b375b36910f3bc0079ff3769652494c647d85ab9e51f3b21c48aac413fa&scene=21#wechat_redirect)  
   
  
[潘立亚](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652907171&idx=1&sn=362d2601e509be48bac0cf11973a9cc0&chksm=f37ec98bc409409dc907f5db7582745ec45d0a5f95c08a26c7bbe367a4611eb613e5cef786c2&token=150064408&lang=zh_CN&scene=21#wechat_redirect)  
  
 [周斌](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652907411&idx=1&sn=0ef5bbcf393f4872f72254660a7bf105&chksm=f37ec8bbc40941ad5b4b1cb1fbb88de8e29bb0baddbf10b51dfb437e0bc055a077616322df72&token=130904846&lang=zh_CN&scene=21#wechat_redirect)  
 [刘新凯](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652907938&idx=1&sn=3e6274dd57ce1d876c3fb00b1945b0c4&chksm=f37ec68ac4094f9c1c4402f6057f799b7e148a1fc0d1d9ea4f49f25bb45f4122772572d9212d&scene=21#wechat_redirect)  
 [杨哲](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652909613&idx=1&sn=67df16379d02cac04dace5d844164bbf&chksm=f37edf05c40956130326f69e161727958ac26a6f90e321c000289e69562f0cff195fe7beb801&scene=21#wechat_redirect)  
 [贺嘉](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652909725&idx=1&sn=b380cd06e9b255d338267f8566b5932e&chksm=f37edfb5c40956a3cfe301123d9404a79a49431bae78771b4f219a80513e53be1051b56453b0&scene=21#wechat_redirect)  
   
  
**学员论文**  
  
[向阳](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652910236&idx=1&sn=648a89a999bcaa65f963840983950440&chksm=f37eddb4c40954a25620b690cf1a515d42b1eba19b786ec52879e56571bdab4ddddafd9fa816&scene=21#wechat_redirect)  
  
 [廖位明](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652910623&idx=1&sn=446ca068552ba4b7001ec2fa9fd199df&chksm=f37edb37c40952213b6a57f2292c39254d431a3a6deb5c4a792e71291b7f33212f7a9630d463&scene=21#wechat_redirect)  
 [张永刚](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652911075&idx=1&sn=aabbf7a89914e8b81b84c60ff78eb88f&chksm=f37edacbc40953dd4e0898510ba0db0a4810782a21e6cba5ad98796fa512ba92dfd4318fff24&scene=21#wechat_redirect)  
 [郑太海](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652911075&idx=1&sn=aabbf7a89914e8b81b84c60ff78eb88f&chksm=f37edacbc40953dd4e0898510ba0db0a4810782a21e6cba5ad98796fa512ba92dfd4318fff24&scene=21#wechat_redirect)  
 [胡广跃](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652911075&idx=1&sn=aabbf7a89914e8b81b84c60ff78eb88f&chksm=f37edacbc40953dd4e0898510ba0db0a4810782a21e6cba5ad98796fa512ba92dfd4318fff24&scene=21#wechat_redirect)  
 [秦峰](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652912131&idx=1&sn=3f4153f4e01869836d2f2c82584865ec&chksm=f37ed52bc4095c3dba90198cf944ba280d4f834f5bdba0ed9ed4fc06f529fb61d7c25fb4476d&scene=21#wechat_redirect)  
 [黄乐](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652913025&idx=1&sn=39cb94b3c9eceedf44bd0cd409273c72&chksm=f37ed2a9c4095bbfce74f2a2437f7f08d8ccfea5e59f880b24f58a1d3b6c760e1b221acb98c4&token=1183061204&lang=zh_CN&scene=21#wechat_redirect)  
 [赵锐](https://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652913430&idx=1&sn=d90fda8dbae488746a6f9c77aaebcbad&chksm=f37ed03ec4095928c3e4456242bfb9f7f6a3e02b53a24fdc3a7cf25f57574c7af28cd4041de4&token=1147989047&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[洪岩  ](http://mp.weixin.qq.com/s?__biz=MzIzMTAzNzUxMQ==&mid=2652914076&idx=1&sn=181c07b8550441e91dd3b8716facf2c6&chksm=f37eaeb4c40927a2180eb3edc342b307abb6598d0af3b57c38076dfb0d99b4e05449fa558aac&scene=21#wechat_redirect)  
[刘峰  ](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247533824&idx=1&sn=2d1ff9d2110aa0fc94f63681182aa8a0&scene=21#wechat_redirect)  
  
  
  
**END**  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/5eH7xATwT38j3Ndib8YhjyiaBQhdzUe1AAfIzicyojXwPTCxD0QGZHhyRcRicJAHhUv382sYFibICoxjzktlJwEEPag/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[]()  
  
[](https://mp.weixin.qq.com/s?__biz=MzU5ODgzNTExOQ==&mid=2247636140&idx=1&sn=8b53ff22bbfa15b46b0ed22fcb3a5f71&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/5eH7xATwT38HPkvxLkOy5rLCeVBtj8H9SUbVPNZbibc4N2knPCDFjTKduRLhiaAZVQShUa2IZqsBShI2GG2dpqBg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
点击这里阅读原文  
  
