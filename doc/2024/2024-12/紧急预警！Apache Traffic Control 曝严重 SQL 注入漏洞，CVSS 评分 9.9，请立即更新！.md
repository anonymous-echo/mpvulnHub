#  紧急预警！Apache Traffic Control 曝严重 SQL 注入漏洞，CVSS 评分 9.9，请立即更新！   
原创 Hankzheng  技术修道场   2024-12-26 01:37  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wWBwsDOJT4icTqwSyiakyxoibxHbE1RhicnSgicJoicsF7b6GTH6lGEoqMLHNpibEQm3nQaWyHAAS7VnwMwLlaq9TICSw/640?wx_fmt=png&from=appmsg "")  
  
**【可导致任意 SQL 命令执行，影响 8.0.1 及以下版本，已发布修复补丁！】**  
  
近日，Apache 软件基金会（ASF）针对其 **Apache Traffic Control**  
 项目发布了紧急安全更新，修复了一个**严重的 SQL 注入漏洞**  
。该漏洞一旦被成功利用，攻击者可以在数据库中执行任意 SQL 命令！  
  
该漏洞被追踪为 **CVE-2024-45387**  
，CVSS 评分高达 **9.9 分**  
，属于“危急”等级！  
  
根据项目维护者发布的公告：“Apache Traffic Control 8.0.1 及以下版本（以及 8.0.0 及以上版本）的 Traffic Ops 中存在一个 SQL 注入漏洞，拥有 'admin'、'federation'、'operations'、'portal' 或 'steering' 角色的特权用户可以通过发送特制的 PUT 请求，对数据库执行任意 SQL。”  
  
**Apache Traffic Control**  
 是一个开源的内容分发网络（CDN）实现，于 2018 年 6 月被 ASF 宣布为顶级项目（TLP）。  
  
**漏洞影响范围：**  
- **Apache Traffic Control 8.0.1 及以下版本**  
- **Apache Traffic Control 8.0.0 及以上版本**  
**修复方案：**  
  
该漏洞已在 **Apache Traffic Control 8.0.2**  
 版本中得到修复。强烈建议所有受影响的用户立即升级到最新版本！  
  
**漏洞发现者：**  
  
腾讯云鼎安全实验室研究员袁罗（Yuan Luo）发现了该漏洞并向 ASF 报告。  
  
**近期其他 Apache 项目漏洞：**  
  
此次更新还伴随着 ASF 对 **Apache HugeGraph-Server**  
（CVE-2024-43441）中一个身份验证绕过漏洞的修复，该漏洞影响 1.0 至 1.3 版本。该漏洞的修复已在 1.5.0 版本中发布。  
  
此外，Apache 最近还发布了针对 **Apache Tomcat**  
（CVE-2024-56337）中一个重要漏洞的补丁，该漏洞在特定条件下可能导致远程代码执行（RCE）。  
  
**安全建议：**  
- **立即更新：**  
 所有 Apache Traffic Control、HugeGraph-Server 和 Tomcat 的用户应立即更新到最新版本，以防止潜在威胁。  
  
- **加强安全意识：**  
 定期进行安全培训，提高员工对安全威胁的认识，警惕可疑的请求和行为。  
  
- **最小权限原则：**  
  严格控制用户权限，仅授予必要的权限，减少攻击面。  
  
**SQL 注入漏洞一直是 Web 安全的重大威胁，此次 Apache Traffic Control 的漏洞再次敲响了警钟。**  
  请所有用户务必重视安全更新，及时修复漏洞，保护自身系统安全！  
  
  
  
