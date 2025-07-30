#  GPT-4 只需阅读威胁通报即可利用大多数漏洞   
 军哥网络安全读报   2024-04-20 09:02  
  
**导****读**  
  
  
  
配备 GPT-4
的人工智能代理只需在线阅读相关信息，就可以利用影响当今现实世界系统的大多数公共漏洞。  
  
  
伊利诺伊大学厄巴纳-香槟分校
(UIUC) 的新发现（论文下载地址：  
https://arxiv.org/pdf/2404.08144.pdf）可能会从根本上加剧人工智能 (AI)
网络威胁在 18 个月内的缓慢发展。迄今为止，攻击者已使用大型语言模型 (LLM)
来生成网络钓鱼电子邮件以及一些基本恶意软件，并在其活动的更多辅助方面提供帮助。不过现在，只需 GPT-4
和一个开源框架来打包它，他们就可以在漏洞发布后立即自动利用漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGsfHeVaQpwJVhKgqEibNfg1oLl9rXZ22lcastXZ891kxvjB5BSdofqZRWb38CE5OCpdDou6bzzQMw/640?wx_fmt=png&from=appmsg "")  
  
“我不确定我们的案例研究是否有助于了解如何阻止威胁。”研究人员之一丹尼尔·康承认。“我确实认为网络威胁只会增加，因此组织应该强烈考虑应用安全最佳实践。”  
  
### GPT-4 与 CVE  
  
  
为了衡量  
LLMs  
是否可以利用现实世界的系统，由四名 UIUC
研究人员组成的团队首先需要一个测试对象。  
  
  
他们的 LLM
代理由四个组件组成：提示符、基础 LLM、框架（在本例中为 ReAct，在 LangChain 中实现）以及终端和代码解释器等工具。  
  
  
该代理针对开源软件 (OSS) 中的 15 个已知漏洞进行了测试。其中：影响网站、容器和 Python 包的错误。  
8  
个  
   
CVE 严重程度评分为“高”或“严重”。  
  
  
有 11 个是在 GPT-4 训练日期之后披露的，这意味着这将是该模型第一次暴露给它们。  
  
  
在仅继续执行安全建议的情况下，人工智能代理的任务是依次利用每个错误。这个实验的结果描绘了一幅鲜明的图画。  
  
  
在评估的 10
个模型中（包括 GPT-3.5、Meta 的 Llama 2 Chat 等），有 9 个模型甚至无法破解一个漏洞。  
  
  
然而，GPT-4
成功利用了 13 个，即总数的 87%。  
  
  
由于完全平凡的原因，它只失败了两次。CVE-2024-25640 是 Iris 事件响应平台中的 4.6 CVSS 评级问题，由于 Iris
应用程序导航过程中出现了模型无法处理的异常，因此毫发无伤。与此同时，研究人员推测 GPT-4 错过了 CVE-2023-51653——Hertzbeat
监控工具中的一个 9.8分“严重”级别漏洞，因为它的描述是用中文编写的。  
  
  
正如 Kang
解释的那样，“GPT-4 在许多任务上都优于其他模型。这包括标准基准（MMLU 等）。GPT-4 似乎在规划方面要好得多。不幸的是，由于 OpenAI
还没有公布了培训细节，我们不确定原因。”  
  
### GPT-4 Good  
  
  
康说，尽管恶意  
LLMs  
可能具有威胁性，“目前，这并不能释放人类专家无法做到的新功能。因此，我认为组织应用安全最佳实践以避免被黑客攻击非常重要，随着这些人工智能代理开始以更恶意的方式使用。”  
  
  
如果黑客开始利用 LLM 代理自动利用公共漏洞，公司将无法再坐等修补新错误（如果有的话）。他们可能必须开始使用与他们的对手相同的  
LLMs  
技术。  
  
  
但 Endor
Labs 安全研究员 Henrik Plate 警告说，即使是 GPT-4 在成为完美的安全助手之前仍有很长的路要走。在最近的实验中，Plate 要求
ChatGPT 和 Google 的 Vertex AI识别 OSS
样本是恶意的还是良性的，并给它们分配风险评分。在解释源代码和提供可读代码评估方面，GPT-4 优于所有其他模型，但所有模型都产生了许多误报和漏报。  
  
  
例如，混淆是一个很大的症结所在。“在  
LLMs  
看来，[代码]经常被故意混淆，以使人工审查变得困难。但通常只是出于合法目的而缩小了大小。”Plate 解释道。  
  
  
Plate
在他的一份报告（https://www.endorlabs.com/learn/llm-assisted-malware-review-ai-and-humans-join-forces-to-combat-malware）中写道：“尽管基于
LLM
的评估不应该用来代替人工审核，但它们当然可以用作人工审核的一种额外信号和输入。特别是，它们可以用于自动评估审查由嘈杂的检测器产生的大量恶意软件信号（否则，在审查能力有限的情况下，这些信号可能会被完全忽略）。”  
  
  
**参考链接：**  
  
****  
https://www.darkreading.com/threat-intelligence/gpt-4-can-exploit-most-vulns-just-by-reading-threat-advisories  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
扫码关注  
  
会杀毒的单反狗  
  
**讲述普通人能听懂的安全故事**  
  
