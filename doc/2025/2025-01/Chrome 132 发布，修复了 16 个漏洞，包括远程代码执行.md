#  Chrome 132 发布，修复了 16 个漏洞，包括远程代码执行   
 网安百色   2025-01-15 11:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo7HICNyc6OJqmy7zyux7qTGYb13Zy8MCJhjR6sLOy6SnOwTq3MmqomXauRhtkorVM04CAt4m4iaEbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Google 已正式将 Chrome 132 发布到稳定频道，为 Windows、macOS 和 Linux 用户带来重要的安全更新和功能增强。  
  
该更新版本为 132.0.6834.83/84，将在未来几天和几周内逐步推出。此版本解决了 16 个安全漏洞，其中几个漏洞构成了远程代码执行 （RCE） 的高风险，强调了立即更新的重要性。  
## 主要安全漏洞  
  
Chrome 132 更新解决了浏览器各个组件中的漏洞，其中五个严重性问题非常突出：  
- **CVE-2025-0434**：Chrome 的 JavaScript 引擎 V8 中存在越界内存访问错误。此缺陷可能允许攻击者使浏览器崩溃或远程执行任意代码。  
  
- **CVE-2025-0435**：Navigation 中的不适当实现，可能导致意外行为或潜在的数据泄露。  
  
- **CVE-2025-0436**：Chrome 的图形引擎 Skia 中存在整数溢出，可能被恶意利用。  
  
- **CVE-2025-0437**：Metrics 中的越界读取可能会暴露敏感数据。  
  
- **CVE-2025-0438**：跟踪中的堆栈缓冲区溢出，可被用于远程代码执行。  
  
解决的其他漏洞包括影响 Frames、Fullscreen、Payments、Extensions 和 Positing 等组件的中低严重性问题。这些修复解决了诸如争用条件、数据验证不足和实施不当等问题。  
  
Google 认为外部安全研究人员发现了其中的许多漏洞，并为每个问题提供了 1,000 到 7,000 美元不等的漏洞赏金。特别是：  
- CVE-2025-0434（V8 内存访问）和 CVE-2025-0435（导航缺陷）获得了 7000 美元的赏金。  
  
- 发现 CVE-2025-0436（Skia 整数溢出）的研究人员获得了 3000 USD 的奖励。  
  
除了外部报告的问题外，Google 的内部安全团队还进行了审核和模糊测试，以发现其他错误。AddressSanitizer 和 MemorySanitizer 等工具在检测这些漏洞方面发挥了至关重要的作用。  
### 为什么要更新  
  
一些已修复的漏洞可能允许攻击者远程执行恶意代码或泄露用户数据。虽然 Google 尚未披露在野外积极利用这些漏洞，但强烈建议用户尽快将 Chrome 更新到版本 132.0.6834.83/84 以降低风险。  
  
要手动更新：  
1. 打开 Chrome。  
  
1. 导航到**“帮助”> Google Chrome**。  
  
1. 允许浏览器检查更新并安装最新版本。  
  
1.   
除了安全修复之外，Chrome 132 还引入了性能改进，并为即将推出的功能做准备，这些功能将在 Google 未来的博客文章中详细介绍。扩展的稳定通道也已更新，以确保企业用户从这些关键修复中受益。  
  
此版本突出了 Google 对浏览器安全和用户安全的持续承诺。鼓励用户保持警惕并保持其软件处于最新状态，以抵御新出现的威胁。  
  
来源：cybersecuritynews  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
