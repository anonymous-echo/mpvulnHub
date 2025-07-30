#  【论文速读】 | AI驱动修复：漏洞自动化修复的未来   
原创 知识分享者  安全极客   2024-03-06 18:05  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8SQnhzsXKBjdwKlfuAUbHZFcYM5niblc6aFA0oFlxGeicgeTb8ygZDttMCqLibviboCPkC28T4oYlFErA/640?wx_fmt=jpeg&from=appmsg "")  
  
本次分享论文为：  
AI-powered patching: the future of automated vulnerability fixes  
  
  
**基本信息**  
  
  
**原文作者：**  
Jan Nowakowski, Jan Keller  
  
**作者单位：**  
Google Security Engineering  
  
**关键词：**  
AI, 安全性漏洞, 自动化修复, LLM, sanitizer bugs  
  
**原文链接：**  
https://storage.googleapis.com/gweb-research2023-media/pubtools/pdf/4fd3441fe40bb74e3f94f5203a17399af07b115c.pdf  
  
**开源代码：**  
[暂无]  
  
  
**论文要点**  
  
  
**论文简介：**  
本  
文介绍了一种利用大语言模型（LLMs）自动修复软件中的安全漏  
洞的方法。  
通过建立一  
个自动化流程，从发现漏洞到生成修复代码，再到测试和人工审查，这一流程  
能够有效加速并提高软件修复的质量和速度。  
  
**研究背景：**随着AI技术的快速发展，其在软件安全领域的应用也越来越广泛。尤其是在自动化发现和修复漏洞方面，AI技术展现出巨大的潜力。  
  
**研究贡献：**  
  
a. 提出了一个完整的AI驱动漏洞修复流程，包括漏洞发现、复现与隔离、生成修复代码、测试和人工审查等步骤。![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QCN2cAOCMcr7EJR2ILAdCWPFJqujU3osWhfAbOS1Y1oXezsgGerMsSLsZg9oHno26KQ20mxhDhRQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
b. 成功利用LLMs自动修复了15%的sanitizer漏洞，大大减少了工程师的工作量。  
  
c. 展示了AI技术在提高软件安全性方面的巨大潜力，为未来的自动化安全防御提供了新的思路。  
  
  
**引言**  
  
  
当前，随着AI技术的不断进步，其在软件开发和安全领域的应用也日益增多。特别是在自动化发现和修复软件漏洞方面，AI提供了一种高效且可行的解决方案。Google的安全工程团队利用大语言模型（LLMs），如Gemini模型，建立了一个自动化的漏洞修复流程。这一流程不仅能自动发现和隔离漏洞，还能生成修复代码供人工审查，极大提高了修复效率和速度。  
  
  
**背景知识**  
  
  
自动化安全漏洞修复技术的研究背景包括了漏洞检测、隔离和修复的整个过程。其中，漏洞检测通常由sanitizers完成，这是一类能在代码运行时检测出各种安全漏洞的工具。随后，通过自动化流程隔离并复现这些漏洞，以便更准确地生成修复代码。最后，修复代码通过自动化测试和人工审查，以确保其正确性和有效性。  
  
  
**论文方法**  
  
  
**理论背景：**  
研究团队利用LLMs的语言生成能力，针对由sanitizers发现的内存安全漏洞，自动生成修复代码。  
这一过程依赖于LLMs强大的模式识别和代码生成能力。  
  
  
**方法实现：**  
通过建立一个从漏洞发现到修复的完整自动化流程，包括漏洞发现、隔离与复现、利用LLMs生成修复代码、代码测试和人工审查等环节。  
在此过程中，研究团队使用了Gemini模型，并通过实验对比不同模型在漏洞修复中的效果。  
  
  
**实验**  
  
  
**实验设置：**  
实验通过自动化流程处理真实世界中的sanitizer漏洞，评估了LLMs在生成有效修复代码方面的能力。  
  
**实验结果：**  
实验结果显示，Gemini模型能够自动修复15%的sanitizer漏洞，相比人工修复大大减少了工作量。  
此外，这一过程还发现不同模型在处理不同类型漏洞时的效率差异，为未来选择最适合的模型提供了参考。  
  
  
**论文结论**  
  
  
本研究展示了利用AI技术，特别是LLMs在自动化修复软件安全漏洞方面的巨大潜力。  
通过自动化的漏洞修复流程，不仅可以加快修复速度，还可以提高软件的安全性。  
未来，随着AI技术的进一步发展，自动化安全漏洞的修复将变得更加高效和普遍。  
  
  
原作者：论文解读智能体  
  
润色：Fancy  
  
校对：小椰风  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/vWuBpewLia8QUiaoVSRUj5mYbjUmJD851ZfeHK53vb8AhFcQrc6BkgibD9wibwGCcAaXI6r1yl5fRiaE5FH6cywPq7w/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/D9wGKNiaQYpx7bvaHqVZibq0ogu5pckjQMepnZgmhgM01uFQsoFz5QDDE0iapRkuUumSGfk8Dz7mjnbvibwPk7jISg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/vWuBpewLia8Tial9kEGMHLEFfCxJSKyicdbUapZVY9gicGwOoL8pp0qKfXJN2ak71fp6uUZiaBa2Az2Ivzdk0HoQrAQ/640?wx_fmt=png&from=appmsg "")  
  
  
