#  vBulletin论坛软件曝出两大漏洞正遭活跃攻击   
鹏鹏同学  黑猫安全   2025-06-02 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9sXQEbl1cgibrsr941GQtlicfUgNs0vtjfEOY6trCQd2vQHUAK25fnDCIYD8hO5gDf8ia4PGbVTNWRQ/640?wx_fmt=png&from=appmsg "")  
  
**vBulletin曝出两大高危漏洞（CVE-2025-48827/CVE-2025-48828）正遭野外利用**  
**未认证攻击者可实现API滥用与远程代码执行，全球论坛系统面临重大威胁**  
### 漏洞核心信息  
1. **CVE-2025-48827（CVSS 10.0）**  
  
1. **影响范围**  
：运行于PHP 8.1+环境的vBulletin 5.0.0-5.7.5与6.0.0-6.0.3版本  
  
1. **攻击方式**  
：通过构造/api.php?method=protectedMethod  
类请求，未授权调用受保护API控制器方法  
  
1. **风险等级**  
：攻击者无需凭证即可完全控制系统  
  
1. **CVE-2025-48828（CVSS 9.0）**  
  
1. **利用手法**  
：滥用模板条件语句实现任意PHP代码执行  
  
1. **关联风险**  
：与前一漏洞形成组合攻击链，进一步扩大危害  
  
### 时间线与攻击态势  
- **2025年5月23日**  
：安全研究员Egidio Romano发现漏洞并发布技术分析，同时公开概念验证（PoC）利用代码  
  
- **2025年5月26日**  
：  
  
- 监测到攻击者针对replaceAdTemplate  
 API端点的野外利用尝试  
  
- 研究员Ryan Dewhurst通过蜜罐捕获波兰IP（195.3.221.137）的活跃攻击行为  
  
### 技术深度解析  
  
Romano在分析报告中强调：  
> "开发者应立即审查框架与自定义API实现——若通过反射（Reflection）动态路由控制器方法，需严格验证访问控制机制。切勿将方法可见性（visibility）视为安全边界，并需跨PHP版本测试应用行为。"  
  
  
同时指出：  
> "此类漏洞模式在PHP生态中普遍存在，除vBulletin外，其他CMS、管理后台及遗留企业系统均可能存在类似风险。"  
  
### 应对建议  
1. **紧急措施**  
  
1. 升级至vBulletin官方最新安全版本  
  
1. 临时禁用PHP 8.1+环境下的API接口（若业务允许）  
  
1. **深度防护**  
  
1. 审计所有反射机制调用的控制器方法  
  
1. 部署WAF规则拦截/api.php  
异常请求模式  
  
1. **威胁监测**  
  
1. 重点关注服务器日志中method=*protected*  
类API调用  
  
1. 监控/includes/api/  
目录下的异常文件写入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9sXQEbl1cgibrsr941GQtlicYNgYJ6GMiayewqlQMsNiawtE9hfXHuCQLf01vPlOoo1ZLdfibb3qjvu8g/640?wx_fmt=png&from=appmsg "")  
  
  
