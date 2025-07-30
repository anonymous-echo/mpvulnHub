> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247489169&idx=1&sn=12e8f36dd27a550376215017f2cf31bd

#  漏洞通告：Sudo Host 选项本地权限提升漏洞（Elevation of Privilege）  
Rich Mirch  securitainment   2025-07-01 09:26  
  
> Vulnerability Advisory Sudo Host Option Elevation of Privilege   
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
  
### 简介  
  
Sudo 是 Linux 系统中常见的高权限命令行工具。它允许授权用户根据系统安全策略，以超级用户（root）或其他用户身份执行命令。Sudo 广泛用于实施最小权限原则（principle of least privilege），让用户无需共享 root 密码即可完成需要提升权限的管理任务，并在系统日志中生成审计记录。  
  
Stratascale Cyber Research Unit（CRU，网络安全研究组）团队近期在 Sudo 中发现了两个本地权限提升（local privilege escalation）漏洞。这些漏洞可导致受影响系统上的权限被提升至 root。  
  
本次研究聚焦于 Sudo 中不常用的命令行选项。本文将详细分析 host  
 选项在 Sudo 中如何被利用（exploited）以在未授权主机上执行命令。  
#### 相关文章  
  
CVE-2025-32463 – Sudo chroot 权限提升漏洞（Elevation of Privilege）  
### 修复建议  
- 安装 sudo 1.9.17p1 或更高版本。  
  
- 参见 https://www.sudo.ws/security/advisories/host_any 获取更多信息。  
  
### 影响范围  
  
CVE-2025-32462 在代码中潜伏超过 12 年未被发现。该漏洞依赖于 Sudo 规则被限制在特定主机名或主机名模式的配置场景下。如果满足这些条件，权限提升到 root 无需任何漏洞利用（exploit）。  
  
已知受影响的版本如下（注意：并非所有区间内版本都已测试）：  
- 稳定版 1.9.0 - 1.9.17  
  
- 旧版 1.8.8 - 1.8.32  
  
已验证可被利用的环境：  
- Ubuntu 24.04.1. Sudo 1.9.15p5, Sudo 1.9.16p2  
  
- macOS Sequoia 15.3.2. Sudo 1.9.13p2  
  
### 管理员 / 蓝队建议  
- 为系统安装最新的 sudo 包。该漏洞无可行的临时缓解措施。  
  
- 检查环境中是否使用了 Host  
 或 Host_Alias  
 选项。审查 /etc/sudoers 及 /etc/sudoers.d 下所有 Sudo 规则。如果 Sudo 规则存储在 LDAP，可用 ldapsearch 等工具导出规则。  
  
#### CVE-2025-32462 - Sudo Host 选项本地权限提升漏洞  
  
CVE-2025-32462 是一个自 host  
 选项 12 年前实现以来就隐藏在代码中的问题。由于这是一个内置选项，无需漏洞利用（exploit）即可提升权限。然而，该问题只能在特定配置下被利用，这些配置使用了企业环境中常见的 Host  
 或 Host_Alias  
 指令。  
  
-h (--host) 选项自 Sudo v1.8.8（2013 年 9 月发布）引入。该选项允许用户列出（list）针对非当前主机的 Sudo 规则。  
  
摘自 NEWS 文件：  
> -h (--host) 选项现在可用于指定主机名。目前仅在 sudoers 插件与 -l (--list) 选项结合时使用。  
  
  
sudoers 配置提供了灵活的语法，满足各类组织的技术需求。无需为不同主机类型维护多份配置文件，只需分发一份 sudoers  
 文件到多台 Linux/UNIX 系统，并通过限制规则适用的用户、组和主机实现差异化管理。  
  
例如，以下 sudoers  
 片段为 lowpriv  
 用户定义了两条规则。该文件分发到三台服务器（prod、dev、ci）。目标是限制其访问生产环境（production），但允许 lowpriv  
 用户完全管理开发环境（development）。  
- 前两行为 Host_Alias  
 指令，定义包含主机列表的变量。  
  
- 第一条规则通过 Host_Alias  
 允许 lowpriv  
 用户在开发服务器（development server）以 root 身份执行所有命令，但明确拒绝其在生产服务器（production server）上的权限。  
  
- 第二条规则明确允许 lowpriv  
 用户在持续集成服务器（ci.test.local）上执行所有命令。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3nHra620U4gXcwbsMtuNkm9iad9gib8E3XuIAYqMr4Q6Wp76oib9Zgw3MA/640?wx_fmt=png&from=appmsg "")  
  
sudoers snippet  
  
执行 Sudo 列表选项（sudo -l）可验证 lowpriv  
 用户在生产服务器上无法运行任何 Sudo 命令，因为 !PROD  
 否定指令明确拒绝了权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK36YNPIZvezgak6rgjjWjD0RMEMBQyr06R7AXe5zOaOSdfPyvZbbbQ7A/640?wx_fmt=png&from=appmsg "")  
  
sudo list option  
  
当用户执行 Sudo 时，系统会比较多个属性以查找匹配规则。若找到匹配，则允许或拒绝命令。通过 /etc/sudo.conf 启用调试后，可获得如下日志（已格式化），用于评估 lowpriv 用户是否可在生产服务器以 root 身份执行命令。尽管用户匹配 SERVERS Host_Alias  
，但由于 !PROD  
 明确否定，最终请求被拒绝，符合预期行为。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3UJSMmN0uxibSfOJkiaMvkQZhfPr1ia69atZj4hkXHMeBgVIc7zZqW26jw/640?wx_fmt=png&from=appmsg "")  
  
sudo conf debugging  
  
-h host 或 --host=host 选项设计初衷是允许用户列出（list）其他主机的 Sudo 规则。当 lowpriv  
 用户使用 host  
 选项执行列表命令时，将显示指定主机的规则。可见 lowpriv  
 用户被允许在 dev.test.local  
 服务器上以 root 执行所有命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3RkeJQQia8TU4AaUA429ugklNXibJltLIViavveUcjGUNF9ApDBkLcXYyQ/640?wx_fmt=png&from=appmsg "")  
  
host option list  
  
检查 Sudo 使用说明可发现 host  
 选项也支持非列表操作（如 sudoedit，sudo -e）。这与文档声明“仅在与 -l (--list) 选项结合时由 sudoers 插件使用”直接冲突。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3RkeJQQia8TU4AaUA429ugklNXibJltLIViavveUcjGUNF9ApDBkLcXYyQ/640?wx_fmt=png&from=appmsg "")  
  
sudo usage statement  
  
Stratascale CRU 团队发现，自 2013 年 host  
 选项引入以来，若在执行 sudo 或 sudoedit 命令时指定了与本地主机无关的远程 host  
 规则，Sudo 会将该规则视为本地有效。结果是，任何被远程主机规则允许的命令都能在本地执行。  
  
即使生产服务器已明确拒绝 lowpriv  
 用户权限，通过指定开发服务器的 host  
 选项，依然可获得 root 权限。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3VPAJ7NN8xBNuJq0iamWZYbIkWdGmTwkYWjNPicLRVn0ibyGuwJDIqmcRQ/640?wx_fmt=png&from=appmsg "")  
  
sudo dev server  
  
同理，指定持续集成服务器（ci.test.local）也可获得完整 root 权限。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK37vic0WcPsPVQEulf83wBZ9zC42dwicP5X9ibLpImfgiaqPV8yu1icmAJQfg/640?wx_fmt=png&from=appmsg "")  
  
sudo test server  
  
查看调试日志可见，所有属性均匹配 ci.test.local  
 的 sudo 规则，允许 lowpriv 用户通过 sudo -i 执行 /bin/bash。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3ENMDry5ErtpI2jOppzskIATmSGPOQRXRyvh6boErM9GGkdIroxUt7w/640?wx_fmt=png&from=appmsg "")  
  
ci.test.local debug log  
  
Sudo 项目开发者兼维护者 Todd Miller 提出的初步修复方案已被验证有效：仅允许在列表操作中指定 host 选项，从而彻底阻断该漏洞利用路径。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3RQkgbjYmVEytqib7AgUb1Gr5EPrflC1CbwBBromb1FhIcTwFujgIibDA/640?wx_fmt=png&from=appmsg "")  
  
Todd Miller's proposed fix  
  
应用补丁后，相关命令执行将因用法错误而失败。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPTPYWObqdwlXYEX0JmRhK3ujsVia8D6ZNcsHYb6Evic12qgM8D5YtkGxanhkfIiay3PrhUg5YDias2pQ/640?wx_fmt=png&from=appmsg "")  
  
execution usage error  
### 披露时间线（Disclosure Timeline）  
  
2025/04/01：漏洞报告提交给 Todd Miller（Sudo 维护者）。  
  
2025/04/03：发送跟进请求，确认已收到初始报告。  
  
2025/04/03：收到确认回复，初步讨论开始。  
  
2025/04/06：维护者提出 CVE-2025-32462 补丁（patch）。  
  
2025/04/07：向 MITRE 申请 CVE 编号。  
  
2025/04/08：MITRE 分配 CVE-2025-32462（host option）和 CVE-2025-32463（chroot）。  
  
2025/04/08：验证 CVE-2025-32462 补丁并提供进一步反馈。  
  
2025/04/23：再次发送跟进请求，询问进展。  
  
2025/05/06：再次发送跟进请求，询问进展。  
  
2025/05/06：维护者回复，仍在处理 chroot 问题的解决方案。  
  
2025/05/07：就 chroot 问题提供反馈。  
  
2025/05/16：再次发送跟进请求。  
  
2025/06/04：再次发送跟进请求。  
  
2025/06/09：维护者提出 CVE-2025-32463 补丁。  
  
2025/06/10：验证 CVE-2025-32463 补丁，并提出披露时间线建议。  
  
2025/06/23：补丁发送至操作系统 distros 邮件列表，Sudo 安全通告链接确认。  
  
2025/06/30：公开披露（Public disclosure）。  
  
2025/06/30：博客文章发布。  
### 致谢与鸣谢（Acknowledgment & Credit）  
  
CVE-2025-32462 Sudo Host Option 提权漏洞（Elevation of Privilege Vulnerability）由 Stratascale Cyber Research Unit（CRU）成员 Rich Mirch 发现。Stratascale CRU 团队感谢 Sudo 维护者 Todd Miller 在漏洞修复过程中的合作与支持。  
  
