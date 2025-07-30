#  谷歌人工智能模糊测试工具AI OSS-Fuzz在开源项目中发现 26 个漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-11-22 01:01  
  
**导****读**  
  
  
  
谷歌透露，其人工智能模糊测试工具
OSS-Fuzz 已被用于帮助识别各种开源代码存储库中的 26 个漏洞，包括 OpenSSL 加密库中的一个中等严重程度的漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHmKXz18BW4rla1ZNW84oVwd2IPGuqDwol2aF2hGJNBIWen9EN4eBu8JweRjDDm6503iaae3dLNpOA/640?wx_fmt=png&from=appmsg "")  
  
  
谷歌开源安全团队在一篇博客文章中表示：“这些特殊的漏洞代表了自动漏洞查找的一个里程碑：每个漏洞都是使用人工智能发现的，使用人工智能生成和增强的模糊测试目标。”  
  
  
有问题的
OpenSSL 漏洞是CVE-2024-9143（CVSS 评分：4.3），这是一个越界内存写入错误，可能导致应用程序崩溃或远程代码执行。该问题已在
OpenSSL 版本 3.3.3、3.2.4、3.1.8、3.0.16、1.1.1zb 和 1.0.2zl 中得到解决。  
  
  
谷歌于 2023 年
8 月增加了利用大型语言模型 (LLM) 来提高 OSS-Fuzz
模糊测试覆盖率的功能，该公司表示，该漏洞可能已在代码库中存在了二十年，并且“通过现有的人工编写的模糊测试目标无法发现该漏洞”。  
  
  
此外，这家科技巨头指出，使用人工智能生成模糊目标已经提高了
272 个 C/C++ 项目的代码覆盖率，增加了超过 370,000 行新代码。  
  
  
“这些错误之所以这么久都未被发现，原因之一是行覆盖率并不能保证某个函数没有错误。”谷歌表示。“代码覆盖率作为一种指标，无法衡量所有可能的代码路径和状态——不同的标志和配置可能会触发不同的行为，从而发现不同的错误。”  
  
  
这些 AI
辅助的漏洞发现也得益于 LLM 被证明能够熟练模拟开发人员的模糊测试工作流程，从而实现更多自动化。  
  
  
本月早些时候，  
Google  
透露，其基于 LLM 的框架 Big Sleep 有助于检测
SQLite 开源数据库引擎中的  
0day  
漏洞。  
  
  
与此同时，谷歌一直致力于将自己的代码库过渡到内存安全的语言，例如
Rust，同时还改进机制以解决空间内存安全漏洞（当一段代码可能访问超出其预期范围的内存时发生）在现有的 C++ 项目（包括 Chrome）中。  
  
  
其中包括迁移到Safe
Buffers和启用强化的 libc++，后者为标准 C++
数据结构添加了边界检查，以消除大量空间安全错误。它进一步指出，由于纳入变更而产生的开销很小（即平均 0.30% 的性能影响）。  
  
  
谷歌表示：“开源贡献者最近添加的强化版 libc++ 引入了一组安全检查，旨在捕获生产中的越界访问等漏洞。虽然 C++ 不会完全实现内存安全，但这些改进降低了风险
[...]，从而带来更可靠、更安全的软件。”  
  
  
谷歌博客文章：  
https://security.googleblog.com/2024/11/leveling-up-fuzzing-finding-more.html  
  
  
**新闻链接：**  
  
https://thehackernews.com/2024/11/googles-ai-powered-oss-fuzz-tool-finds.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
