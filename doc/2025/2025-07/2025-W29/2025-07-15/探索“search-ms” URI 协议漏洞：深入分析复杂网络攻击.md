> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531762&idx=2&sn=99867009f3948281421488758c28df39

#  探索“search-ms” URI 协议漏洞：深入分析复杂网络攻击  
 Ots安全   2025-07-15 10:38  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
理解“search-ms” URI 协议  
  
“search-ms”协议是 Windows 操作系统的一个合法功能，旨在启动默认桌面搜索应用程序。它允许用户通过 URL 创建搜索查询，提供了一种方便的文件和文件夹定位方式。然而，与许多内置功能一样，当与恶意意图结合时，它可能被操纵。攻击者通过精心设计的超链接或电子邮件附件利用该协议，将用户重定向到攻击者控制的网站，从而启动感染链。  
  
网络攻击揭秘  
  
@1ZRR4H的帖子（https://x.com/1ZRR4H/status/1944835848752566756）揭示了这一漏洞的具体实例。攻击始于托管在 http://196.251.71[.]46/ 的 HTML 页面，该页面滥用“search-ms” URI 协议，将用户重定向到位于 45.151.62[.]238 的远程 WebDAV 服务器。WebDAV（Web 分布式创作和版本控制）是 HTTP 协议的扩展，允许通过网络进行协作编辑和文件管理。然而，如果未使用更新的 SSL 证书进行保护，其漏洞使其成为攻击者的主要目标。一旦重定向，攻击会分发伪装成 PDF 文档的 LNK（快捷方式）文件。  
  
这些文件利用 Adobe Acrobat 品牌欺骗用户，使其认为打开的是合法文档。根据 2024 年 McAfee 研究，用户手动访问 LNK 文件时会触发感染链，该研究显示 LNK 恶意软件的季度增长率达 30%。在本次攻击中，LNK 文件调用 Windows 命令处理器（cmd.exe），执行恶意代码，可能导致勒索软件、数据盗窃或其他有害后果。  
  
图片 1：目录索引显示了“Adobe Acrobat.exe”和“Acrobat.html”等文件，暗示使用合法软件名称进行欺骗。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafXGeOfM5DaiaxmqaQVlialOD7e92INSghibIKNyH0x5cjAmwNSbX8LyNG2OY3OggX3uaWjPwn9teGjA/640?wx_fmt=png&from=appmsg "")  
  
图片 2：模仿 Adobe Acrobat 的提示，要求用户打开受保护文件，这是典型的社交工程策略。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tafXGeOfM5DaiaxmqaQVlialODbESqQBLPUx4PT3xZR4jqNsVknySDECZNvwia9ZicfDic47X2esthibJh9w/640?wx_fmt=jpeg&from=appmsg "")  
  
图片 3 & 4：文件资源管理器视图显示伪装的 LNK 文件（“Autofin.pdf”）及其属性，揭示了恶意意图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafXGeOfM5DaiaxmqaQVlialOD8cRXL7UCM3BYWJKNzsWVrwhrcSIEgmymdkIlXMpuPE3htj33ZlZhzg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafXGeOfM5DaiaxmqaQVlialODjnuDIHFwe1hjWaUfpM6wJjPMp5fdcpUic81CPAErz6hicOGicAichXDmicA/640?wx_fmt=png&from=appmsg "")  
  
威胁格局  
  
此攻击技术是协议处理程序滥用这一更广泛趋势的一部分，该方法最早由 2022 年 5 月的研究人员详细描述，并于 2024 年 dfir.ch 研究中得到扩展。“search-ms”漏洞的灵活性在于它能够绕过传统安全措施，例如杀毒软件，通过利用 Windows 内置功能。以下是与此攻击相关的关键威胁：  
  
1. 勒索软件部署  
  
根据 2023 年 PCRisk.com 报告，伪造软件更新的使用方式与本次攻击的模式一致。一旦执行 LNK 文件，它可以下载并安装勒索软件，将用户锁定在系统外，并要求支付解密费用。  
  
2. 数据盗窃和间谍活动  
  
恶意代码可以窃取敏感信息，例如登录凭据或财务数据，并将其传输到攻击者控制的服务器。WebDAV 服务器在此链条中的角色便于隐秘地传输被盗数据。  
  
3. 广泛感染潜力该技术依赖 HTML 附件和欺骗性电子邮件，扩大了其覆盖范围。2024 年 Comparitech.com 分析指出，未受保护的 WebDAV 服务器是高频漏洞，增强了攻击的可扩展性。  
  
4. 逃避检测  
  
由于攻击利用了合法的 Windows 协议，它可以逃避传统安全工具的检测，对 IT 管理员构成了重大挑战。根据 2022 年 FieldEffect.com 的咨询，微软尚未发布最终补丁，缓解措施成为主要防御手段。  
  
漏洞的技术机制  
  
感染链可分解为以下几个步骤：  
- 初始诱饵：用户遇到指向恶意 HTML 页面的超链接或电子邮件附件。  
  
- 重定向：“search-ms” URI 触发重定向到 WebDAV 服务器，利用其漏洞。  
  
- 文件分发：服务器分发伪装成 PDF 的 LNK 文件，利用社交工程促使用户交互。  
  
- 执行：打开 LNK 文件执行 cmd.exe，启动恶意软件负载。  
  
这一过程得到了 Trellix（2024 年）的研究支持，该研究识别出攻击者控制页面上的 JavaScript 是“search-ms”漏洞的关键启用因素，扩展了其 HTML 附件的范围。  
  
结论  
  
“search-ms” URI 协议漏洞，如 @1ZRR4H X 帖子所述，代表了一种复杂的网络攻击，融合了社交工程与技术漏洞。通过利用 WebDAV 服务器和伪装的 LNK 文件，攻击者可以绕过传统防御措施，带来勒索软件、数据盗窃和广泛感染的重大风险。截至 2025 年 7 月 15 日，微软尚未提供立即修复，用户和组织需实施强有力的缓解策略。保持信息更新和主动性是应对这一动态网络安全格局及其未来威胁的关键。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
