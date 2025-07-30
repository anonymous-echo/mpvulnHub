#  0day漏洞量产？AI Agent“生产线”曝光   
原创 腾讯程序员  腾讯技术工程   2025-06-05 12:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/j3gficicyOvasVeMDmWoZ2zyN8iaSc6XWYj79H3xfgvsqK9TDxOBlcUa6W0EE5KBdxacd2Ql6QBmuhBJKIUS4PSZQ/640?wx_fmt=gif&from=appmsg "")  
  
作者：悟空团队 — 新一代 AI 代码安全捉“妖”行者（原腾讯AI安全-啄木鸟团队)  
>  丨   
导语  
   
随着AI技术的迅猛发展，AI智能体在0day漏洞挖掘领域展现出前所未有的潜力。  
> 本文将深入探讨AI Agent如何通过创新的多智能体协作系统，打造出高效的0day漏洞“生产线”，实现自动化的漏洞检测。通过基准测试和实战验证，Agent在复杂代码和大型项目中的表现超越传统工具，极大提升了漏洞识别效率与准确性。  
  
### 一、AI Agent 颠覆0day挖掘认知  
  
在网络安全攻防的核心战场，0day漏洞挖掘长期以来被视为一项极度依赖专家经验、耗时费力的“手艺活”。  
  
传统的0day挖掘如同大海捞针，依赖人工审计和静态应用安全测试（SAST）工具，虽有其作用，但在应对日益庞杂的代码和系统时，往往面临误报、漏报和效率低下等问题，在处理大型项目、复杂代码系统时，它们的局限性也逐渐显现。  
    
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0OZlbgx9Hiauicj1SF6IJDZIgiaickJYyThdcJU2R6yDfZGI21nrGQuJG2A/640?wx_fmt=png&from=appmsg "")  
  
（插画图：AI Agent 与传统漏洞挖掘方式对比）  
  
AI Agent 的出现，正为这一困境带来革命性的突破。通过模拟人类专家的分析与推理能力，结合机器学习的强大模式识别能力，AI Agent 不仅能大幅度自动化审计流程、减轻人工负担，更能精准识别出传统方法难以发现的复杂漏洞，显著提升漏洞挖掘的效率、准确性和深度。  
  
### 二、“0day生产线”是如何建成的？  
  
AI Agent 通过构建一个多智能体协作系统，效仿专业安全团队的协作机制，从而打造出一条自动化的0day漏洞“生产线”。  
## 1.  系统架构：协同作战的智能军团  
  
(1)  
   
   
Client Agent ：  
用户交互的入口，负责提交任务并与其他智能体进行协调。  
  
(2)  
   
   
Remote Agent ：  
负责任务规划与路由，负责将复杂任务分解，并依据各专业智能体的能力进行最优分配，确保整体任务高效执行。  
  
(3)  
   
   
Audit Agent ：  
审计智能体，  
漏洞挖掘的核心执行单元。它负责对代码进行从代码片段级到完整项目级的多层次、多维度扫描与风险评估。集成了多种先进扫描技术和算法，以增强审计的广度和深度。  
  
(4)  
   
   
Review Agent ：  
复审智能体，负责进一步审核漏洞检测结果，结合多种Prompt和评分机制，确认漏洞的有效性和严重性，大幅降低误报。  
  
(5)  
   
   
Fix Agent ：  
修复智能体，  
此智能体负责提供初步的修复建议。它通过查询CVE漏洞库、内部知识库等，生成漏洞修复方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0ApDakBL6gyQ5xSmm0eEMlkFjfmx4uBcJULX22TkG6kqDia5UuLmSekw/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 AI Agent 架构图）  
  
悟空 Agent 的核心优势在于，它通过精细分工克服了单一智能体在知识广度、分析深度和任务并行处理能力上的局限，使得复杂漏洞的挖掘如同专家团队高效会诊，而非单兵作战。通过A2A（Agent-to-Agent）协议高效协同，确保任务从宏观规划到微观执行的无缝衔接。  
  
  
2.  
   
   
工作流程：自动化的流水线作业  
  
悟空 Agent 的工作流程高度自动化，宛如一条精密的流水线：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM082uf6X9tczicfDRicunby1cY2ebgtiaQg4OaJEB3uY4PypkropibXib9vAA/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 Agent 工作流程图）  
  
(1)  
   
   
任务接收与分解：  
 用户通过  
Client Agent   
提交任务。该任务首先到达“产线总指挥”——  
 Remote Agent   
。它利用大语言模型（LLM）进行任务规划，将复杂需求智能分解为独立的子任务（如代码审计、结果验证、修复方案生成）。  
  
(2)  
   
   
并行专业处理：  
 分解后的子任务被自动派发至“流水线”上的各个专业“工站”——即并行的  
Audit Agent 、Review Agent 和 Fix Agent 。  
  
●  
   
Audit Agent   
运用LLM和代码分析模块（如入口识别、上下文获取、漏洞推理）执行深度扫描。  
  
●  
   
Review Agent   
利用LLM及多重校验、投票机制（如多Checker、疑难点反思）确保结果准确性。  
  
●  
   
Fix Agent   
参考知识库（CVE库、内部库），借助LLM微调生成修复建议并进行语法检查。  
  
(3)  
   
   
结果汇总输出：  
 各智能体完成工作后，将处理响应反馈给  
Remote Agent   
。由它负责整合所有子任务的结果，形成一份完整的、经过层层处理的最终报告或解决方案，并准备交付。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0Abp9nicF96L3DKRKBbpxJcmEcNTkZ6NTrXVuEcR4aKVOd4ibOUNAVjAg/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 Agent 的实际工作流程界面）  
  
这个流程通过明确的分工和智能体的并行协作，实现了从任务输入到结果输出的高度自动化，显著提升了漏洞挖掘与处理的效率。  
  
### 三、AI Agent 的产出与实战验证  
## 1.  基准数据测试：  
### ● GitHub Top 1000开源项目实战验证  
  
为全面评估悟空 Agent 在真实且复杂的代码环境中的实战能力，**我们选取了 GitHub 平台某语言排名前1000的开源项目作为基准测试集**  
，直接对这些广泛使用的代码仓库进行真实漏洞扫描与检测。  
  
在测试中，悟空 Agent 展现出高效且精准的漏洞识别能力。**特别是在针对SQL注入等常见高危漏洞的检测上，准确率超95%**  
。  
  
在对GitHub Top 1000项目的整体扫描中，**悟空 Agent 共计发现并确认了 247 处有效漏洞**  
。这些漏洞在不同影响力层级的项目中均有分布，具体构成请见下图分析：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0jNicL8Jtdn9OPDHQBpjFRF6g5qrCPRWZ65ZwI3VZXtQQHxUZ1bdYJUg/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 Agent 在 Github 某语言下Top1000项目的实战检测成果）  
  
从图中可以看出，虽然顶级项目安全防护相对严密，但中长尾项目中仍存在大量可被利用的风险点。我们也对大部分检出漏洞进行了 CVE 编号申报，申报结果大致分布为：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0W6fF4fz4gHjp52rhlcj3JEkicUv6viadMxI2RF3aib0Vo1fCII686T4aQ/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 Agent检出漏洞的 CVE 申报情况）  
  
  
2.  
   
   
实战验证  
### ● 中大型开源项目  
  
在对Github 某 23k Stars 的中大规模开源项目的实战审计中，悟空 Agent 的表现与传统静态应用安全测试（SAST）工具形成了鲜明对照。具体差异可总结如下：  
<table><tbody><tr><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">对比维度</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">传统SAST工具</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><strong><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">悟空 A</span></strong><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">gent</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td></tr><tr><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">有效漏洞发现</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">检出数量有限，难以深入复杂逻辑</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">检出较多</span><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;"> (项目中 &gt;15个未披露漏洞)</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td></tr><tr><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">误报情况</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">误报率通常</span><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">极高</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">误报率</span><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">显著降低</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td></tr><tr><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">分析能力</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">侧重已知模式匹配，表层分析为主</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">深度逻辑推理</span><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">，理解复杂输入与上下文</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td></tr><tr><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">审计效率</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">大量误报耗费人工甄别时间</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td><td><p style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;margin: 0pt 0px 0pt 0pt;padding: 0px;display: block;unicode-bidi: embed;line-height: 30px;min-height: 1.8em;max-width: 100%;text-align: justify;"><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">更聚焦高价值风险，</span><span leaf="" style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;color: rgb(62, 71, 83);font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;background-color: rgb(255, 255, 255);text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;float: none;display: inline !important;">提升人工效率</span><span style="border-color: rgb(227, 230, 235);border-style: solid;border-width: 0px;box-sizing: border-box;max-width: 100%;"></span></p></td></tr></tbody></table>  
我们在持续迭代工具之余，也及时向项目官方和 CVE 官方纰漏了漏洞细节：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0K0u08oBezgfdqdtzwiaScr12HbLfBNsxpZnPRzInw6lHjRTUoBQ50jw/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空团队向项目官方披露漏洞细节及修复建议邮件）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0vkZXdKAzIwSvDtRH01oSJOyq7hCafxxDQEnPEDPsEf5HfpLT6vBghA/640?wx_fmt=png&from=appmsg "")  
  
（图：CVE 官方授予悟空团队漏洞编号的邮件）  
### ● 大型开源项目  
  
为进一步检验悟空 Agent 在处理超大规模、高复杂度项目上的实战效能，我们选取了当前 AI 领域中广受瞩目且代码量庞大的开源项目 Langchain 作为目标，Langchain其复杂的架构、众多的依赖关系以及快速的迭代周期，对任何自动化安全审计工具而言都是一项严峻的挑战。  
  
面对如 LangChain 这样超 100K Stars 的大型项目，悟空 Agent 依然展现出其强大的分析推理能力，通过细致的扫描和智能研判，**悟空 Agent 成功在Langchain中识别出若干此前未被发现的潜在安全漏洞。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvavEUbrr3lFiagmLHBP1Z4uM0xjl15jaNic4Px8o6ZBkGxKukuiaapdj4SibWAk2z5Knnffy5grZgqRibJQ/640?wx_fmt=png&from=appmsg "")  
  
（图：悟空 Agent 后台检出 LangChian 项目的未纰漏漏洞）  
  
我们高度重视这些发现，并已遵循负责任的漏洞披露原则，将相关的技术细节和潜在风险点整理后，已通过官方渠道或指定的第三方漏洞报告平台（如面向AI/ML项目的Huntr）正式报送给 Langchain 项目维护团队及相关安全应急响应中心。  
  
  
### 四、结语  
  
悟空 Agent 是 AI 在漏洞挖掘领域应用的成功案例，通过创新的多智能体协作模式，将0day漏洞的发现效率和准确性提升到了新的高度。AI技术的持续进化，正驱动网络安全迈向智能化、自动化新高度。这不仅是场技术革命，更是安全理念的升华——AI旨在赋能而非取代安全专家。  
  
我们应积极拥抱这场变革，通过深化人机协同，共筑更智能、主动且更具韧性的网络安全新范式。这将使安全专家得以从重复劳动中解放，专注于战略性与创新性挑战，最终推动整个网络安全生态实现跨越式提升。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/j3gficicyOvasVeMDmWoZ2zyN8iaSc6XWYjZ7Hx6Udjjk2BGLzC9ahJq7ibxDd1RGA0c9NYZc1husEsvb3tY4FcWPQ/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/j3gficicyOvasVeMDmWoZ2zyN8iaSc6XWYj5q5PQEOc5ibURPb03vnRibrxC3UR8xzdyATfiawTYRV2vJvBnAIcE1FeQ/640?wx_fmt=png&from=appmsg "")  
  
