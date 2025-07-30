#  CISA警告：黑客仍在利用 Log4Shell 漏洞   
 关键基础设施安全应急响应中心   2022-06-27 14:51  
  
CISA 和美国海岸警卫队网络司令部 (CGCYBER) 警告说，民族国家的黑客仍在利用 Log4Shell(CVE-2021-44228)，专门针对未打补丁的、面向Internet的VMware Horizon和Unified Access Gateway服务器。这种情况至少自2021年12月即 Log4Shell 发现一个月后开始发生。  
  
“作为这种利用的一部分，可疑的 APT 参与者在受感染的系统上植入了加载程序恶意软件，其中嵌入了可执行远程命令和控制 (C2) 的可执行文件，”CISA 警告说。“在一个确认的妥协中，这些 APT 参与者能够在网络内部横向移动，访问灾难恢复网络，并收集和泄露敏感数据。”  
  
**受 Log4Shell 影响的其他 1,872 种产品**  
  
CISA警报强调产品安全团队需要额外注意识别任何包含风险 Log4j 包的软件。但是，安全团队不应止步于修补 VMware Horizon 和 Unified Access Gateway 服务器：我们的记录显示，Log4Shell 漏洞目前影响了 1,800 多种产品。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QmbJGbR2j6wUwCJULdhV5AV45OOWFib5azAg6jM2WFY5pCxkibqWEoR9hqdTQlFYwC1f3rqPudpWnmV7uWg57M9Q/640?wx_fmt=png "")  
  
图注：VulnDB 记录显示受 Log4j 影响的软件  
  
在我们2021年终漏洞快速查看报告中，我们强调了 Log4Shell 具有广泛影响的潜力，并观察到与任何其他漏洞（包括Heartbleed、POODLE 和 Spectre v2）相比，它有更多的参考。根据我们的研究，自该报告发布以来，受影响的产品总数增加了 11.6%。随着我们继续跟踪漏洞，受 Log4Shell 影响的产品总数可能会增加。  
  
Log4Shell跟踪为CVE-2021-44228（CVSS 评分：10.0），是一个远程代码执行漏洞，影响广泛的消费者和企业服务、网站、应用程序和其他产品使用的 Apache Log4j 日志库。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/QmbJGbR2j6wUwCJULdhV5AV45OOWFib5aDxBG3Hk6Dprt5LmAldsibezMu7OzMDMY4qUtozJQq09aeX8NRIg8WMw/640?wx_fmt=jpeg "")  
  
**如何掌握漏洞**  
  
为了防止 Log4Shell 漏洞利用尝试和其他可能被利用的漏洞，组织应该了解所有已知受影响的供应商和产品。  
为了更全面地了解，他们还需要了解没有 CVE ID 的漏洞。  
  
自 Log4Shell 发现以来， VulnDB一直在跟踪此信息，并将详细信息汇总到其易于使用的平台中。事实上，我们的描述和解决方案信息中已经解释了 VMware 的确切易受攻击机制。使用该元数据，VulnDB 用户可以确保他们不会受到持续的利用尝试。  
  
**漏洞和威胁参与者喋喋不休**  
  
除了了解您面临的关键漏洞和供应链/第三方弱点之外，组织还必须了解威胁参与者正在积极讨论和寻求在非法社区中利用哪些漏洞。这个关键的上下文可以告知安全团队可以积极优先处理的流程（例如修补），以修复潜在的风险漏洞，例如 Log4Shell。  
  
**查看 Flashpoint 漏洞管理解决方案的实际应用**  
  
除了 VMware 和 Unified Access Gateway 之外，可能还有许多其他产品目前容易受到 CVE-2021-44228 的攻击。注册免费的 VulnDB 试用版，以了解当前受 Log4Shell 影响的所有受影响的供应商和产品。  
  
  
  
原文来源：  
E安全  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg "")  
  
