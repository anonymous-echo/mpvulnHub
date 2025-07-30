#  [安全开源分享] Datacon24漏洞赛道冠军分享：vuln_wp——大模型赋能的漏洞自动化分析全解析（武大）   
原创 0817 IOTG团队  娜璋AI安全之家   2025-03-22 19:07  
  
该资源是来自武汉大学0817 IOTG团队，DataCon 2024漏洞分析赛道冠军的开源和解题分享，其开源提供了漏洞情报提取与漏洞挖掘两大核心模块的解决框架，并打包成一个可执行 Docker 镜像压缩包，方便安全研究者和开发者快速部署体验自动化漏洞分析。极其适合开发者、研究者、学生学习和应用。快来 Github 点个 Star ⭐，Fork 🍴并 Watch👀， 试试吧！希望对大家有所帮助。  
  
**其开源地址如下：**  
- https://github.com/123f321/datacon24_vuln_wp  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNtSs8urf3ic4Z7bQe9XlByAbqqqZEaRxVGAq8otxh19W0ArrfT6ufcqiax2icBib86dHTW9zNMdUiclMg/640?wx_fmt=png&from=appmsg "")  
  
  
文章目录：  
- **🔥 什么是 Datacon？**  
  
- **🔥 什么是 datacon24_vuln_wp？**  
  
- **🎯 项目背景与设计初衷**  
  
- **🛠 核心模块与技术亮点**  
  
- **1. 情报提取模块**  
  
- **2. 漏洞挖掘模块**  
  
- **🌟 项目优势**  
  
- **💡 如何参与与贡献**  
  
- **🚀 结语**  
  
# 🔥 什么是 Datacon？  
  
DataCon大数据安全分析竞赛是由奇安信集团、清华大学于2019年联合发起，是国内首个以大数据安全分析为目标的大型竞赛，旨在选拔和培养积极防御型网络安全人才，竞赛的最大特点是强调“实战化”，模拟真实网络环境的攻防对抗场景，重点考察选手利用新技术方法解决不同场景下安全问题的能力，目前已连续举办五届。比赛主页：  
- https://www.datacon.org.cn/competition/competitions/91/introduction  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNtSs8urf3ic4Z7bQe9XlByAnvXiaJxOh3cUBEqiaTxtmsibWYPMSuhGwHRGRZIXibLYXOrfCb0PeMG72w/640?wx_fmt=png&from=appmsg "")  
# 🔥 什么是 datacon24_vuln_wp？  
  
datacon24_vuln_wp 是基于 datacon 2024 漏洞分析赛道冠军战队 0817iotg 的完整解题方案，开源提供了漏洞情报提取与漏洞挖掘两大核心模块的解决框架，并打包成一个可执行 **Docker 镜像压缩包**  
，方便安全研究者和开发者快速部署体验自动化漏洞分析。  
  
项目地址如下，包含详细源码分析，记得点赞喔！  
- https://github.com/123f321/datacon24_vuln_wp  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNtSs8urf3ic4Z7bQe9XlByATw2UQHMEhhcickvibTHlaX89YBqkuhRrWOcUETzXvLlUwYV2YCf6rBNg/640?wx_fmt=png&from=appmsg "")  
# 🎯 项目背景与设计初衷  
- **安全需求驱动**  
在网络安全和漏洞挖掘领域，海量漏洞分析文章和庞大的代码库常常让传统人工和静态分析方法捉襟见肘。datacon24_vuln_wp 正是为了解决这一问题而设计，利用大模型的深度语义理解能力，实现自动化、智能化的漏洞检测与信息提取。  
  
- **冠军战队方案基础**  
项目基于赛道冠军战队 0817iotg 的完整解题框架，融合了最新的提示工程方法和多轮大模型调用机制，旨在降低误报、提高漏洞识别的准确率和效率。  
  
# 🛠 核心模块与技术亮点  
## 1. 情报提取模块  
- **任务目标**  
：快速从大量漏洞分析文章中提取关键摘要信息，涵盖文件名、漏洞编号、厂商/产品名称、编程语言、漏洞成因、危险函数、以及 POC/EXP 相关信息等多维度数据。  
  
- **技术框架**  
：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNtSs8urf3ic4Z7bQe9XlByAG5yM2JERYh6iaWrH7OdLDAiatIwK5iajeBCtoTb2kYNbHibSRPD2fDK4ibQ/640?wx_fmt=png&from=appmsg "")  
- **技术实现**  
：  
  
- 利用 **BeautifulSoup4**  
 对 HTML 进行解析，精准过滤图片等无关内容。  
  
- 采用精细化的提示工程方法，将信息拆分成多个输出维度，使用两次大模型调用分别判定，确保提取结果准确且具备多角度分析。  
  
- 内置投票机制，对多轮大模型输出进行校验，自动剔除不合理或低置信度结果。  
  
- 扩展功能：除基础信息外，还能识别版本信息、修复建议，并从文章中提取 POC/EXP 代码和图像内容。（详见 task1_source_code 中的 test.py、appendix.py 及 pic_expand.py）  
  
## 2. 漏洞挖掘模块  
- **任务目标**  
：针对传统静态审计费时费力的问题，自动化识别代码中的潜在漏洞，实现精准定位。  
  
- **技术框架**  
：  
  
![在这里插入图片描述](https://mmbiz.qpic.cn/mmbiz_png/0RFmxdZEDRNtSs8urf3ic4Z7bQe9XlByAmtYJ0TgWq0icn31G9UiaJC22MWy60sOvgtphSXS5Jqy4wJwcosg3TibZQ/640?wx_fmt=png&from=appmsg "")  
  
- **技术实现**  
：  
  
- 先对待分析文件进行大小排序、类型过滤，再依据编程语言进行函数级别的切分，确保每个代码片段都能单独分析。  
  
- 利用提示工程进行初步筛查，提取可能包含漏洞的种子函数；对种子函数内容进行深度解析，针对不同漏洞类型（如 race condition、SQL 注入、double-fetch、buff_overflow、command_injection 等）采用不同分析策略。  
  
- 部分复杂漏洞类型引入 RAG 技术，结合多轮提示与结果投票，有效降低误报，并输出最有可能的漏洞函数供后续手工验证或自动修复。  
  
# 🌟 项目优势  
- **大模型助力**  
利用最新大模型技术和提示工程，实现高效、精准的信息提取与漏洞定位。  
  
- **多轮校验机制**  
通过多次调用大模型和投票比对，显著降低输出不确定性，提高漏洞检测准确率。  
  
- **开箱即用**  
提供完整的 Docker 压缩包，无需复杂环境配置，支持快速部署和现场测试。  
  
- **全 Python 实现**  
代码结构清晰、模块化设计，方便开发者二次开发、扩展与定制。  
  
- **丰富的实践案例**  
内置针对多种漏洞类型的示例与测试数据，为新手和资深安全研究者提供了宝贵的实战参考。  
  
# 💡 如何参与与贡献  
- **获取项目**  
访问 GitHub 仓库   
https://github.com/123f321/datacon24_vuln_wp  
 下载源代码和 Docker 镜像。  
  
- **开源互动**  
欢迎 Star ⭐、Fork 🍴、Watch 👀，关注项目动态；提出 Issue 或提交 PR，大家一起完善自动化漏洞分析工具。  
  
- **实践分享**  
利用该框架进行漏洞挖掘与安全审计，将实战经验分享到社区，共同推动安全技术的进步。  
  
# 🚀 结语  
  
datacon24_vuln_wp 为网络安全领域提供了一种自动化漏洞分析思路，利用大模型与精细提示工程，实现了从情报提取到漏洞定位的全流程智能化处理。无论你是安全研究新手还是资深专家，这个项目都将提供一定帮助，助力构建更安全的数字世界。立即加入我们，共同探索自动化漏洞分析的无限可能！  
  
最后，分享不易，赶快前往 GitHub，尤其从事大模型漏洞挖掘和参与DataCon的同学，体验这一前沿的漏洞分析自动化解决方案吧！  
- https://github.com/123f321/datacon24_vuln_wp  
  
(By: 武大0817团队 2025-03-21 夜于贵州)  
  
  
