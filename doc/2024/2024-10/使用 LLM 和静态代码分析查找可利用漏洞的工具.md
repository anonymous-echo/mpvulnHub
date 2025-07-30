#  使用 LLM 和静态代码分析查找可利用漏洞的工具   
原创 星空浪子  星空网络安全   2024-10-20 20:08  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/n4Jw29uPBiclpy7aopkpj2Tt4vLGJGZPgtxD7WcYic72MGcZgicFvoFpsZgytODT2nKRHBg8EjNpqukeAnbN1ZKEw/640?wx_fmt=other&from=appmsg "")  
  
在当今不断发展的网络安全环境中，识别代码库中的漏洞对于维护安全的软件和基础设施至关重要。Vulnhuntr 是一款可在 GitHub 上获取的开源工具，它利用  
大型语言模型  
(LLM) 和静态代码分析来识别基于 Python 的项目中可远程利用的漏洞。Vulnhuntr 的设计简洁而强大，弥补了智能自动化和深度代码分析之间的差距，使其成为开发人员、安全专业人员和组织的宝贵资源。  
  
Vulnhuntr 的工作原理  
  
Vulnhuntr 采用独特的多阶段方法进行漏洞检测：  
1. LLM 支持的 README 分析：  
 LLM 首先分析项目的 README 文件，了解代码库的功能和潜在漏洞。这些信息用于指导后续分析。  
  
1. 初始代码扫描：  
 LLM 对整个代码库进行初始扫描，根据对安全编码实践和常见漏洞模式的理解标记潜在漏洞。  
  
1. 上下文深度挖掘：  
对于每个潜在漏洞，Vulnhuntr 都会为 LLM 提供漏洞专用提示，从而触发更深入的分析。LLM 会智能地从相关文件中请求更多上下文，跟踪从用户输入到服务器端处理的数据流。这使其能够识别跨多个文件和功能的漏洞。  
  
1. 综合漏洞报告：  
 Vulnhuntr 生成一份详细报告，概述其发现的内容。该报告包括：  
  
1. 每个文件的初步评估结果  
  
1. 具有上下文功能和类别参考的二次评估结果  
  
1. 每个漏洞的置信度分数  
  
1. 分析过程的日志  
  
1. 针对已验证漏洞的概念验证 (PoC) 攻击  
  
在存储库中发现的示例漏洞  
  
Vulnhuntr 在最近的扫描中发现了多个备受瞩目的项目中的漏洞，展示了其有效性：  
- gpt_academic  
（64k 颗星）：   
LFI  
、  
 XSS  
  
- ComfyUI  
（50k 颗星）：   
XSS  
  
- FastChat  
（35k 颗星）：   
SSRF  
  
- 删除（29k 颗星）：  
 RCE、IDOR  
  
- Ragflow  
（16k 颗星）：   
RCE  
  
这些发现说明了 Vulnhuntr 可以检测到的漏洞类型的多样性，从  
学术研究工具中的  
LFI到机器学习项目中的  
  
RCE  
。  
  
限制  
  
虽然 Vulnhuntr 代表了漏洞扫描领域的重大进步，但它也存在一些局限性：  
- Python 支持：  
目前，该工具仅支持 Python 代码库。  
  
- 漏洞类别：  
 Vulnhuntr 可以识别一组特定的漏洞类别，包括 LFI、AFO、RCE、XSS、SQLI、SSRF 和 IDOR。  
  
结论  
  
Vulnhuntr 将 LLM 与静态代码分析相结合，为漏洞检测带来了一种新方法，既提供高级分析，又提供深入洞察。它能够从代码库的相关部分动态请求上下文，从而确保全面覆盖，而其使用 PoC 漏洞和置信度评分进行的最终分析则为开发人员和安全团队提供了可操作的信息。  
  
地址：  
  
```
https://github.com/protectai/vulnhuntr?tab=readme-ov-file#installation
```  
  
  
希望这些信息对您有所帮助！如果觉得这篇文章有价值，  
**欢迎点赞、分享、再看、转载，**  
如果您有网络安全的疑问，联系我随时为您解答，感谢您的支持！  
  
