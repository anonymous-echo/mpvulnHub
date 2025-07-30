#  GitLab安全通告 | 修复了XSS 和帐户接管漏洞   
 夜组OSINT   2025-04-25 00:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A1iaTj8eIk1SSvkOGg93dHicZxnUtJGrfvvT0H05mDuuCv0P7M2EmOeNXcIZXiaqcULl1ic0iaAJiavkc3g/640?wx_fmt=png&from=appmsg "")  
  
GitLab 发布了一份安全公告，敦促用户立即升级其自主管理的 GitLab 安装。公告重点介绍了 GitLab 社区版 (CE) 和企业版 (EE) 的 17.11.1、17.10.5 和 17.9.7 版本，以解决“重要的错误和安全修复” 。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A2Qyvfrgt0M9icvpjPCnG0dqSRiaDYul7sCGq1xhnlPkLHSDwXydNvIl80WInAMAQlVtibVcbiaQbEeWA/640?wx_fmt=png&from=appmsg "")  
## XSS和帐户接管风险  
  
该公告详细说明了多个漏洞，包括 Maven Dependency Proxy 中的多个高危跨站脚本 (XSS) 问题。这些漏洞可能允许“在特定条件下在用户浏览器中进行跨站脚本攻击和内容安全策略绕过”，影响 16.6 至 17.9.7 之前的版本、17.10 至 17.10.5 之前的版本以及 17.11 至 17.11.1 之前的版本。  
  
GitLab 已为这两个 XSS漏洞分配了 CVE-2025-1763 和 CVE-2025-2443编号，CVSS 评分均为 8.7，表明其严重性级别较高。这些漏洞的发现归功于 joaxcar，他通过 GitLab 的 HackerOne 漏洞赏金计划进行了贡献。  
  
此外，Maven 依赖代理中发现了一个网络错误日志 (NEL) 标头注入漏洞，该漏洞存在“跟踪用户浏览活动，可能导致账户完全接管”的重大风险。该漏洞编号为 CVE-2025-1908，CVSS 评分为 7.7。  
## 拒绝服务和未授权访问漏洞  
  
除了跨站脚本 (XSS) 和帐户接管风险外，该通告还解决了一个中等严重程度的拒绝服务 (DoS)漏洞， “通过问题预览影响服务可用性”。该漏洞编号为 CVE-2025-0639，影响 16.7 至 17.9.7 之前的版本、17.10 至 17.10.5 之前的版本以及 17.11 至 17.11.1 之前的版本。Sigitsetiawansss 是此漏洞的报告者。  
  
最后，一个访问控制问题可能导致“在项目中禁用存储库资产时，未经授权访问分支名称”。此漏洞编号为 CVE-2024-12244，影响 17.7 至 17.9.7 之前的版本、17.10 至 17.10.5 之前的版本以及 17.11 至 17.11.1 之前的版本。Mateuszek 通过 HackerOne 项目报告了此问题。  
## 安全建议  
  
GitLab 强烈建议“所有运行受下述问题影响版本的用户尽快升级到最新版本”。用户应升级到 17.11.1、17.10.5 或 17.9.7 版本，以降低这些安全风险。  
  
  
  
