#  如何使用大型语言模型（LLMs）自动检测BOLA漏洞   
FreddyLu666  FreeBuf   2024-10-04 09:30  
  
##   
  
  
本文介绍了对一种名为 BOLABuster 的方法所进行的研究，该方法使用大型语言模型 (LLM) 来检测对象级授权损坏（BOLA）漏洞。通过大规模自动化 BOLA 检测，我们将在识别开源项目中的这些漏洞方面取得令人鼓舞的结果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGqWibUcob4hQNdKZPf8Npjia882Gx3Od5ibHvBia27Gbf9N42licdbN9UZbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
BOLA 是现代 API 和 Web 应用程序中广泛存在且可能非常严重的漏洞。虽然手动利用 BOLA 漏洞通常很简单，但自动识别新的 BOLA 却很困难，原因如下：  
> 1、应用程序逻辑的复杂性；  
> 2、输入参数的多样性；  
> 3、现代 Web 应用程序的状态特性；  
  
  
  
由于这些原因，模糊测试和静态分析等传统方法无法有效检测 BOLA，因此手动检测成为标准方法。  
  
  
为了应对这些挑战，我们利用 LLM 的推理和生成功能来自动执行传统上手动完成的任务。这些任务包括：  
> 1、了解应用程序逻辑；  
> 2、识别端点依赖关系；  
> 3、生成测试用例并解释测试结果；  
  
  
  
通过将 LLM 与启发式方法相结合，我们的方法可以实现大规模的全自动 BOLA 检测。虽然我们的研究还处于早期阶段，但我们已经成功发现了内部和开源项目中的不少 BOLA 漏洞。其中包括以下漏洞：  
> 1、Grafana (CVE-2024-1313)  
> 2、Harbor (CVE-2024-22278)  
> 3、Easy!Appointments (CVE-2023-3285 至 CVE-2023-3290 和CVE-2023-38047 至 CVE-2023-38055)；  
  
##   
  
**自动化 BOLA 检测的挑战**  
  
  
## 正如之前的研究所揭露的那样，当 API 应用程序的后端无法验证用户是否具有访问、修改或删除对象的正确权限时，就会发生 BOLA。  
  
  
下面展示了一个简单的 BOLA 示例。在这个医疗应用中，患者可以使用下面这个API 来访问医生就诊记录：  
```
api.clinic[.]site/get_history?visit_id=XXXX
```  
  
  
每位患者只能访问自己的医疗记录。但是，如果服务器未能正确验证此逻辑，恶意患者可能会操纵请求中的visit_id参数来访问其他患者的数据。下图显示了恶意 API 调用中的这种操作：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGBDqfR1ffaQAmWAYvxLICcD9KIznRFqrHoia9bOO5RZjuEf9hq7MXMnQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
尽管 BOLA 的概念很简单，但自动化检测却面临巨大挑战。与其他常见漏洞（例如 SQL 注入、跨站点脚本 (XSS) 和缓冲区溢出）不同，静态应用程序安全测试 ( SAST ) 和动态应用程序安全测试 ( DAST ) 等安全测试工具无法有效识别 BOLA。这些工具依赖于已知的漏洞模式和行为，而这些模式和行为并不适用于 BOLA。目前尚无用于检测 BOLA 的自动化工具。  
  
  
此外，目前还没有开发框架可以帮助开发人员预防 BOLA。因此，需要审计 BOLA 的安全团队必须手动审查应用程序并创建自定义测试用例。一些技术挑战加剧了自动化 BOLA 检测的难度：  
> 1、复杂的授权机制：现代 API 应用程序通常具有复杂的授权机制，涉及多个角色、资源类型和操作。这种复杂性使审计人员难以确定应允许用户对特定资源执行哪些操作。  
> 2、有状态属性：大多数现代 Web 应用程序都是有状态的，这意味着每个 API 调用都可以更改应用程序的状态并影响其他 API 调用的结果。换句话说，调用一个 API 端点的响应取决于其他 API 端点的执行结果。这种复杂的逻辑通常内置于 Web 界面中，用于指导最终用户与应用程序进行正确的交互。但是，自动从 API 规范中逆向工程逻辑并跟踪应用程序状态并不容易。  
> 3、缺乏漏洞指标：BOLA 是一种逻辑错误，没有编译器或 SAST 工具可以识别的已知模式。在运行时，BOLA 不会触发任何错误或表现出揭示问题的特定行为。成功利用的输入和输出通常会导致状态代码为 200 的成功请求，并且它们不包含任何可疑的有效负载，因此很难发现漏洞。  
> 4、上下文相关输入：BOLA 测试涉及操纵 API 端点的输入参数以识别漏洞。此过程需要精确定位引用敏感数据的参数并为参数提供有效值以运行测试。我们完全依赖 API 规范来了解每个端点的功能和参数，因此很难确定端点是否会泄露或操纵敏感数据。确定目标端点及其参数后，下一步是向这些端点发送请求并观察其行为。确定测试的特定参数值很困难，因为只有映射到系统中现有对象的值才能触发 BOLA。使用传统的模糊测试技术自动生成此类有效载荷既具有挑战性又无效。  
  
##   
  
**BOLABuster：人工智能辅助 BOLA 检测**  
  
  
## 鉴于生成式人工智能 (Gen-AI) 的最新进展以及自动化 BOLA 检测的挑战，我们决定通过开发 BOLABuster 来解决人工智能问题。BOLABuster 方法利用 LLM 的推理能力来理解 API 应用程序并自动执行以前手动且耗时的 BOLA 检测任务。  
  
  
BOLABuster 的算法如下图所示，仅需要目标 API 应用程序的 API 规范作为输入。BOLABuster 根据 API 规范生成所有测试用例，BOLABuster 目前支持OpenAPI 规范 3，这是最广泛采用的 API 规范格式：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGeicTjlmaYhMBOUPJ5wticoHLyppaAmMeMFFiblIVwrBZqHA4KRGeM4ZwA/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**BOLABuster 方法涉及到的五个主要阶段**  
  
  
## 识别潜在易受攻击的端点 (PVE)  
  
  
我们方法论的第一阶段是识别可能易受 BOLA 攻击的 API 端点。我们重点关注经过身份验证的端点，这些端点具有唯一标识系统中数据对象的输入参数，例如username、email、teamId、invoiceId和visitId。如果后端无法验证授权逻辑，则具有这些参数的端点可能易受 BOLA 攻击。  
  
  
AI 可协助分析每个端点的功能和参数，以确定哪些端点引用或返回敏感数据。下图显示了一组可能存在漏洞的端点：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGCaX1tibq8X2IxTzD48jPtV64JXnwOImC390zSg7hOPpjp3svbGiaP9Zg/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 发现端点依赖关系  
  
  
此阶段分析应用程序逻辑以发现 API 端点之间的依赖关系。由于现代 Web 应用程序的状态特性，在测试之前了解 API 端点的先决条件至关重要。例如，要测试购物车应用程序的结帐 API，必须先将商品添加到购物车。此操作需要知道itemId和customerId。  
  
  
我们将为其他端点输出所需参数的端点归类为生产者，将摄取这些参数的端点归类为消费者，如下图所示。每个端点都可以同时充当生产者和消费者，AI 协助分析每个端点的功能和参数，以确定一个端点是否可以输出另一个端点输入所需的值：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGzxfkEEAevg2mVicFib3RZiaCDqFvbWx7972qs7MIZQlRw9Movxlic0rDzQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
###   
### 生成执行路径和测试计划  
  
  
此阶段使用前两个阶段的输出为每个 PVE 构建依赖关系树。每个节点代表一个 API 端点，从父节点到子节点的每条边代表一种依赖关系，其中父节点是消费者，子节点是生产者。每棵依赖关系树的根都是一个 PVE，从每个叶节点到根的路径代表一条可以到达 PVE 的执行路径。然后，我们为每个执行路径创建一个测试计划，该计划由所有 PVE 的执行路径及其 API 调用组成。下图显示了具有四条执行路径的依赖关系树的示例：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGw7lp0ozNLsH8795mGSRl7zYRFbOiazRQlWPIy0G50786bMUKJEqrlMQ/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 创建测试脚本  
  
  
此阶段使用 LLM 将每个执行路径转换为可执行的 bash 脚本。每个脚本都会对目标服务器进行一系列 API 调用，从登录以检索身份验证令牌开始，到调用 PVE 结束。每个测试脚本至少涉及两个经过身份验证的用户，其中一个用户尝试访问另一个用户的数据。如果一个用户可以成功访问或操纵另一个用户的数据，则表明存在 BOLA。下图演示了 BOLA 测试的高级示例，测试涉及两个用户 Alice 和 Bob，他们登录系统并接收唯一的身份验证令牌。Alice 在系统中创建了一篇文章，并对这篇文章发表了评论。然后将文章和评论的标识符传递给 Bob。然后 Bob 尝试执行未经授权的操作 - 试图删除 Alice 的评论。如果操作成功，则表明存在潜在的 BOLA：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGl3plnp86pEvaQTiby8VYda4qBoG5808WuAB0T8a3CoFPgfUtVSTOwqA/640?wx_fmt=jpeg&from=appmsg "")  
###   
### 执行计划并分析  
  
  
在此阶段，BOLABuster 针对目标 API 服务器执行测试脚本，然后分析响应以确定 PVE 是否容易受到 BOLA 攻击。我们自动化用户注册、用户登录和令牌刷新流程，以确保每个测试计划不间断地执行。  
  
  
BOLABuster 按照特定顺序运行同一 PVE 的测试用例，以最大程度地减少它们之间的依赖关系。例如，我们避免让一个测试用例删除另一个测试用例需要的对象。  
  
  
本质上，我们确保执行路径内除对 PVE 的调用之外的所有 API 调用均成功。此调用的结果应表明 PVE 是否容易受到 BOLA 攻击。  
  
  
排序算法确保在应用程序进行任何访问尝试之前，已填充必要的数据。BOLABuster 将包含更新或删除用户或资源等操作的测试脚本安排在执行序列的末尾，以防止尝试获取已删除或已修改的资源。  
  
  
每个测试计划的日志和输出均由 AI 分析。当 AI 认为某个端点存在漏洞时，人工会验证结果以评估 PVE 在应用环境中的影响。  
  
  
虽然我们利用人工智能实现尽可能多的任务自动化，但人工验证仍然必不可少。我们的实验表明，人工反馈可以不断提高人工智能的准确性和可靠性。  
##   
  
**总结**  
  
  
##   
  
我们的研究表明，人工智能在彻底改变漏洞检测和安全研究方面具有巨大潜力。通过利用 LLM 来自动执行以前手动且耗时的任务，我们证明了人工智能可以充当可靠的助手。这不仅适用于编写代码，还适用于调试和识别漏洞。  
  
  
尽管我们的研究仍处于早期阶段，但其影响深远。我们为 BOLA 检测开发的算法可以扩展到识别其他类型的漏洞，为漏洞研究开辟新的途径。随着人工智能技术的不断发展，我们预计类似的方法将使一系列以前不切实际或不可能实现的安全研究计划成为可能。  
  
  
值得注意的是，这项技术可能是一把双刃剑。虽然防御者可以使用人工智能来增强其安全措施，但对手可以利用同一技术更快地发现零日漏洞并升级网络攻击。  
  
  
以人工智能对抗人工智能的理念从未如此重要，因为我们努力用更智能、更精确的人工智能驱动解决方案战胜对手。网络安全界必须保持警惕，积极主动地制定战略，以应对人工智能带来的潜在威胁。  
##   
  
**参考文献**  
  
  
> https://grafana.com/security/security-advisories/cve-2024-1313/  
> https://nvd.nist.gov/vuln/detail/CVE-2024-22278  
> https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-3285  
> https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-3290  
> https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-38047  
> https://cve.mitre.org/cgi-bin/cvename.cgi?name=2023-38055  
> https://unit42.paloaltonetworks.com/new-bola-vulnerability-grafana/  
> https://unit42.paloaltonetworks.com/bola-vulnerability-impacts-container-registry-harbor/  
> https://unit42.paloaltonetworks.com/bola-vulnerabilities-easyappointments/  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://unit42.paloaltonetworks.com/automated-bola-detection-and-ai/  
  
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
