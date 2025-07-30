#  GitLab 多个漏洞可导致攻击者完全接管账户  
会杀毒的单反狗  军哥网络安全读报   2025-06-13 01:02  
  
**导****读**  
  
  
  
GitLab 社区版 (CE) 和企业版 (EE) 平台上存在一系列严重的安全漏洞，攻击者可以利用这些漏洞完全接管帐户并破坏整个开发基础设施。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaEwGHZkvHktLibiaekoa7LUEVI8gm2TqYzZKM0vLiaY56k5thn60X8Beic4b2gofsXmx0l9R9tL74GP9g/640?wx_fmt=png&from=appmsg "")  
  
  
GitLab发布了紧急补丁版本 18.0.2、17.11.4 和 17.10.8，以解决十个不同的安全漏洞，其中一些漏洞的 CVSS 严重程度评分超过 8.0。  
  
  
这些漏洞影响全球数百万个 GitLab 安装，并对组织的源代码存储库、CI/CD 管道和敏感开发数据构成重大风险。  
  
### 账户接管漏洞  
###   
  
最严重的漏洞 CVE-2025-4278 存在 HTML 注入缺陷，CVSS 评分为 8.7，攻击者可以通过向 GitLab 的搜索功能注入恶意代码来实现完全的帐户接管。  
  
  
安全研究员 joaxcar 通过 GitLab 的 HackerOne 漏洞赏金计划发现了这个严重漏洞，漏洞影响从 18.0 开始到 18.0.2 之前的所有 GitLab CE/EE 版本。  
  
  
除了这一威胁之外，CVE-2025-2254 为一个跨站点脚本 (XSS)漏洞，其 CVSS 评分同样为 8.7。  
  
  
该漏洞使攻击者能够在代码片段查看器中执行恶意脚本，从而允许他们冒充合法用户并在其安全环境中执行未经授权的操作。  
  
  
该漏洞影响 GitLab CE/EE 17.9 到 17.10.8 版本、17.11 到 17.11.4 版本以及 18.0 到 18.0.2 版本。  
  
### CI/CD DoS攻击  
###   
  
GitLab Ultimate EE 客户还面临 CVE-2025-5121 这一高严重性威胁，这是一个缺少授权的漏洞，CVSS 评分为 8.5。  
  
  
该漏洞可能允许经过身份验证的攻击者将恶意CI/CD作业注入 GitLab Ultimate 实例中任何项目的所有未来管道中。  
  
  
该漏洞影响 GitLab Ultimate EE 17.11 到 17.11.4 之前的版本以及 18.0 到 18.0.2 之前的版本，可能会危及整个软件开发和部署过程。  
  
  
多个拒绝服务漏洞加剧了这些风险，包括 CVE-2025-0673（CVSS 7.5），它使攻击者能够触发无限重定向循环，导致服务器内存耗尽。  
  
  
其他 DoS 向量包括 CVE-2025-1516 和 CVE-2025-1478，分别利用无限制的 webhook 令牌名称和板名称，两者的 CVSS 分数均为 6.5。  
  
  
这些漏洞影响了 8.7 和 8.13 版之前的 GitLab 安装，表明存在长期存在的安全漏洞。  
  
### 建议立即修补  
###   
  
GitLab 强烈建议所有受影响的系统立即升级到最新版本。  
  
  
这些漏洞涉及多种部署类型，包括 Omnibus、源代码安装和 Helm 图表，需要跨不同的基础设施配置进行全面的修复工作。  
  
  
组织应优先立即升级受影响的系统。  
  
  
所有面向客户的系统和数据托管环境都必须遵守最高安全标准，因此这些补丁对于维护安全的开发环境至关重要。  
  
  
安全团队应在下一个可用的维护时段内实施这些更新，以防止这些严重漏洞的潜在利用。  
  
  
新闻链接：  
  
https://cybersecuritynews.com/gitlab-vulnerabilities-allows-account-takeover/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
