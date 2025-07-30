> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323069&idx=3&sn=e1a2654d1eb8eb944bf1949b9ed09b40

#  GitLab曝高危漏洞组合，攻击者可实现完全账户接管  
 FreeBuf   2025-06-13 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38Tl4wYSAtXiaoFKOv5riaQkxBLlYjfFdvFxichpDEuKDKCb0x4iaRebVSpSicZpBuFZFT6bicPfCNvwRUA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
GitLab 社区版（CE）和企业版（EE）平台近期曝出一系列关键安全漏洞，攻击者可利用这些漏洞实现完全账户接管，进而入侵整个开发基础设施。该公司已紧急发布 18.0.2、17.11.4 和 17.10.8 三个补丁版本，修复了十个独立安全缺陷，其中多个漏洞的 CVSS 严重性评分超过 8.0。  
  
  
这些漏洞影响全球数百万 GitLab 实例，对企业的源代码仓库、CI/CD 流水线和敏感开发数据构成重大风险。  
  
### Part01  
### 账户接管漏洞  
###   
  
最严重的漏洞 CVE-2025-4278 是一个 HTML 注入漏洞（CVSS 评分 8.7），攻击者可通过向 GitLab 搜索功能注入恶意代码实现完全账户接管。安全研究员 joaxcar 通过 GitLab 的 HackerOne 漏洞赏金计划发现了这一关键缺陷，影响所有 18.0 至 18.0.2 之前的 GitLab CE/EE 版本。  
  
  
与之形成威胁组合的是 CVE-2025-2254（XSS 跨站脚本漏洞，CVSS 评分同样为 8.7）。该漏洞允许攻击者在代码片段查看器中执行恶意脚本，从而冒充合法用户在其安全上下文中执行未授权操作。受影响的版本包括 17.9 至 17.10.8 之前、17.11 至 17.11.4 之前以及 18.0 至 18.0.2 之前的 GitLab CE/EE 版本，显示出这些安全缺陷的广泛影响范围。  
  
### Part02  
### CI/CD 拒绝服务攻击  
###   
  
GitLab Ultimate EE 用户还面临 CVE-2025-5121 的高危威胁（授权缺失漏洞，CVSS 评分 8.5）。该漏洞可使经过认证的攻击者向 GitLab Ultimate 实例中任何项目的未来流水线注入恶意 CI/CD 任务，影响范围包括 17.11 至 17.11.4 之前和 18.0 至 18.0.2 之前的版本，可能破坏整个软件开发和部署流程。  
  
  
多个拒绝服务（DoS）漏洞进一步加剧风险，包括：  
- CVE-2025-0673（CVSS 7.5）：可触发无限重定向循环导致服务器内存耗尽  
  
- CVE-2025-1516 和 CVE-2025-1478（CVSS 均为 6.5）：分别利用无限制的 webhook 令牌名称和看板名称发起攻击  
  
值得注意的是，这些漏洞的影响可追溯至 8.7 和 8.13 版本，反映出长期存在的安全隐患。  
  
### Part03  
### 紧急修复方案  
###   
  
GitLab 强烈建议所有自托管实例立即升级至最新补丁版本，并确认 GitLab.com 已部署安全修复。这些漏洞影响多种部署类型（包括 Omnibus、源代码安装和 Helm 图表），需要针对不同基础设施配置进行全面修复。  
  
  
企业应优先升级受影响系统。根据 GitLab 的负责任披露政策，漏洞细节将在补丁发布 30 天后公开。该公司强调所有面向客户的系统和数据托管环境都必须遵循最高安全标准，这些补丁对维护安全开发环境至关重要。安全团队应在最近的可维护窗口期内实施更新，以防这些严重漏洞遭到利用。  
  
  
**参考来源：**  
  
**Multiple GitLab Vulnerabilities Allow Attackers to Achieve Complete Account Takeover**  
  
https://cybersecuritynews.com/gitlab-vulnerabilities-allows-account-takeover/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651322946&idx=1&sn=c9cbbd848459bfe0a36fa121ff364ad0&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
