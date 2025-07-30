#  LockBit 勒索软件利用严重的 Citrix Bleed 漏洞进行入侵   
原创 铸盾安全  河南等级保护测评   2023-11-29 00:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoFVexAEAGUvWARRWpBRaicIsFFWOWj05J1E85n2TSibdmYiaqAbSiaHjIWHhETucyjOA7mhsF7rpfrnvg/640?wx_fmt=png&from=appmsg "")  
  
包括 LockBit 勒索软件附属公司在内的多个威胁参与者正在积极利用  
Citrix NetScaler 应用程序交付控制 (ADC) 和网关设备中最近披露的一个关键安全漏洞，以获得对目标环境的初始访问权限。  
  
该联合咨询来自美国网络安全和基础设施安全局 (CISA)、联邦调查局 (FBI)、多州信息共享和分析中心 (MS-ISAC) 以及澳大利亚信号局的澳大利亚网络安全中心 (ASD 的 ACSC) 。  
  
“已知 LockBit 3.0 附属公司利用 Citrix Bleed，威胁行为者可以绕过密码要求和多因素身份验证 (MFA)，从而成功劫持 Citrix NetScaler Web 应用程序交付控制 (ADC) 和网关设备上的合法用户会话， ”有关机构表示  
。  
  
“通过接管合法用户会话，恶意行为者获得了更高的权限来获取凭据、横向移动以及访问数据和资源。”  
  
该漏洞的编号为CVE-2023-4966  
（CVSS 评分：9.4），Citrix 上个月已解决该漏洞，但至少自 2023 年 8 月起该漏洞就被武器化为零日漏洞。该漏洞的代号为 Citrix Bleed。  
  
公开披露后不久，谷歌旗下的 Mandiant透露  
，它正在跟踪四个不同的未分类 (UNC) 组织，这些组织参与利用 CVE-2023-4966 来瞄准美洲、欧洲、中东和非洲和亚太及日本地区的多个垂直行业。  
  
最新加入漏洞利用行列的威胁参与者是 LockBit，据观察，该公司利用该缺陷执行 PowerShell 脚本，并删除 AnyDesk 和 Splashtop 等远程管理和监控 (RMM) 工具以进行后续活动。  
  
这一事态发展再次强调了这样一个事实：暴露服务中的漏洞仍然是勒索软件攻击的主要入口。  
  
在此披露之际，Check Point 发布了针对 Windows 和 Linux 的勒索软件攻击的比较研究，指出大多数侵入 Linux 的勒索软件家族大量使用 OpenSSL 库以及 ChaCha20/RSA 和 AES/RSA 算法。安全研究员马克·萨利纳斯·费尔南德斯 (Marc Salinas Fernandez)表示  
：“与 Windows 威胁相比，Linux 勒索软件显然针对中型和大型组织，而 Windows 威胁本质上更为普遍。  
”  
  
对各种针对 Linux 的勒索软件系列的检查“揭示了一种有趣的简化趋势，它们的核心功能通常被简化为基本的加密过程，从而将其余的工作留给脚本和合法的系统工具。”  
  
Check Point 表示，这种极简主义方法不仅使这些勒索软件系列严重依赖外部配置和脚本，而且还使它们更容易在雷达下飞行。  
  
