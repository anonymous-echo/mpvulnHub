#  Windows 远程桌面网关漏洞使系统面临 DoS 攻击   
 网安百色   2025-01-15 11:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo7HICNyc6OJqmy7zyux7qTGeDSxsopMg8NGw0daiaAU7lriaibnthmotusS1JuYiaDtXlv0ZIf73CU71w/640?wx_fmt=jpeg&from=appmsg "")  
  
Microsoft 在其 Windows 远程桌面网关 （RD Gateway） 中披露了一个重大漏洞，该漏洞可能允许攻击者利用争用条件，从而导致拒绝服务 （DoS） 攻击。  
  
该漏洞被确定为 CVE-2025-21225，已在该公司 2025 年 1 月的周二补丁更新中得到解决。  
  
当系统的行为取决于并发操作中事件的时间或顺序时，就会出现争用条件漏洞，而攻击者利用这种缺乏同步的情况。  
  
在 CVE-2025-21225（Windows 远程桌面网关 （RD Gateway） 拒绝服务漏洞）的上下文中，在 RD 网关服务处理网络请求期间出现争用条件。  
### Windows 远程桌面网关漏洞  
  
该漏洞源于分类为 **CWE-843：使用不兼容类型访问资源**的类型混淆问题。此缺陷允许攻击者利用绑定到网络堆栈的 RD 网关组件，使其可通过 Internet 远程利用。通过成功触发争用条件，攻击者可以破坏 RD 网关服务的可用性。  
  
虽然现有连接不受影响，但新连接可能会被阻止，这可能会导致服务在反复利用后无法使用。  
  
这种类型的拒绝服务攻击对依赖 RD Gateway 进行安全远程访问的组织构成了严重风险。尽管该漏洞不会阻止数据盗窃或远程执行代码，但对系统可用性的影响非常大。  
  
该漏洞影响 Windows Server 的多个版本，包括：  
- **Windows Server 2016**（核心和标准安装）  
  
- **Windows Server 2019**（核心和标准安装）  
  
- **Windows Server 2022**（核心和标准安装）  
  
- **Windows Server 2025**（核心和标准安装）  
  
每个受影响的版本都收到了具有唯一标识符的安全更新。例如：  
- Windows Server 2019：更新 KB5050008（内部版本 10.0.17763.6775）  
  
- Windows Server 2022：更新 KB5049983（内部版本 10.0.20348.3091）  
  
- Windows Server 2025：更新 KB5050009（内部版本 10.0.26100.2894）  
  
利用此漏洞需要攻击者赢得争用条件，这对于熟练的威胁行为者来说是一项具有挑战性但并非不可能的任务。该漏洞因其可能破坏关键服务而被评为“重要”，但目前没有公开可用的漏洞利用代码。  
  
截至 2025 年 1 月 15 日，没有报告或证据表明 CVE-2025-21225（Windows 远程桌面网关 （RD 网关）拒绝服务漏洞）已在野外被积极利用。此外，尚未披露针对此漏洞的概念验证 （PoC） 漏洞利用或公开漏洞利用工具。  
### 缓解措施和建议  
  
Microsoft 已发布补丁作为其 2025 年 1 月安全更新的一部分，以解决此漏洞。强烈建议组织立即应用这些更新，以降低漏洞利用的风险。  
  
另外：  
- 确保强大的网络监控，以检测针对 RD Gateway 服务的异常活动。  
  
- 通过防火墙规则，将 RD 网关的公开范围限制为仅受信任的网络。  
  
- 考虑为远程访问实施额外的安全层，例如 VPN 或多因素身份验证。  
  
2025 年 1 月的周二补丁日更新解决了 Microsoft 生态系统中的 159 个漏洞，包括 8 个零日漏洞和几个关键的远程代码执行漏洞。  
  
虽然 CVE-2025-21225 未被归类为严重，但其对服务可用性的潜在影响凸显了主动补丁管理和系统强化的重要性。  
  
来源：cybersecuritynews  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
