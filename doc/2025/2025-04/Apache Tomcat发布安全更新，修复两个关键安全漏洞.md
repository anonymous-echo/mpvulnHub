#  Apache Tomcat发布安全更新，修复两个关键安全漏洞   
原创 ralap  网络个人修炼   2025-04-30 02:24  
  
Apache 软件基金会于近日发布了针对其著名 Servlet 容器   
Apache Tomcat  
 的安全更新，修复了两个关键的安全漏洞，分别被编号为 CVE-2025-31650 和 CVE-2025-31651。这些漏洞可能影响用户的应用服务器安全性，并导致拒绝服务（DoS）或安全策略绕过等风险。  
  
漏洞详情  
  
CVE-2025-31651  
  
漏洞类型：转义、元字符或控制序列处理不当（Improper Neutralization of Escape, Meta, or Control Sequences）  
  
严重程度：低危，目前暂无评分  
  
受影响版本：  
  
Apache Tomcat 11.0.0-M1 至 11.0.5  
  
Apache Tomcat 10.1.0-M1 至 10.1.39  
  
Apache Tomcat 9.0.0.M1 至 9.0.102  
  
描述：  
  
在某些特定的 rewrite 规则配置下，攻击者可以通过构造特殊请求绕过部分重写规则。如果这些 rewrite 规则用于实施重要安全约束（如访问控制），则可能导致这些安全机制被完全绕过，从而带来潜在的权限提升或敏感信息泄露风险。  
  
该漏洞的利用前提是存在不常见的 rewrite 配置，因此实际攻击面有限，但其影响范围广泛，建议所有符合条件的用户及时升级以消除隐患。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibzPyZkTnSBo6Mzk58mGgjDokbzb9GN2DbiaarF2SURiaQggtmt2SPOaaFg/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2025-31650  
  
漏洞类型：输入验证不当（Improper Input Validation）  
  
严重程度：高危，暂无评分  
  
受影响版本：  
  
Apache Tomcat 9.0.76 至 9.0.102  
  
Apache Tomcat 10.1.10 至 10.1.39  
  
Apache Tomcat 11.0.0-M2 至 11.0.5  
  
描述：  
  
此漏洞存在于对 HTTP 优先级头部（HTTP/2 Priority Headers） 的错误处理过程中。当接收到格式错误的优先级头部时，Tomcat 并未正确清理失败请求，造成内存泄漏。攻击者可发起大量恶意请求，最终耗尽内存资源并触发 OutOfMemoryException，导致服务不可用（拒绝服务攻击 DoS）。  
  
这一漏洞无需任何身份认证即可利用，且影响多个主流版本分支，因此被认为具有较高威胁性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibzIZJ9hDa9VdhFtBiaS7g7rJWgS8EHtT8bibdOSDhTFYmB7nX60bMSaJUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibzdqt9XD16Hpn6SK1tpNdXCXUGqiaBicib0Oia2icfBEEBKIoDE41dDGfSOLw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞修复方法：  
  
Tomcat 9.0.104  
  
Tomcat 10.1.40  
  
Tomcat 11.0.6  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibzu61riaHBj1h1ZUiakx9mUSYgLqjkwrIGdftGf7nfrUPoSelNX769YkxQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibznF1mE9MNrlm1GfLd49lotDslyYvhG7XYzns8mzk68U7HiaVoxSXGLmA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5y2fUaoQPfJNHDvhFeCwFBZRicicL2B9ibzs23icdYtganzH6OUgIGYrdXt2z3NK5Z9eibDhQcfy7kEgTNJoaoiapmmw/640?wx_fmt=png&from=appmsg "")  
  
参考链接：  
  
[1]https://www.cve.org/CVERecord?id=CVE-2025-31650  
  
[2]https://www.cve.org/CVERecord?id=CVE-2025-31651  
  
[3]https://tomcat.apache.org/security-11.html  
  
[4]https://tomcat.apache.org/security-10.html  
  
[5]https://tomcat.apache.org/security-9.html  
  
[6]https://www.openwall.com/lists/oss-security/2025/04/28/2  
  
[7]https://lists.apache.org/list.html?announce@tomcat.apache.org  
  
  
  
-End-  
  
  
  
**如果觉得我的分享有用**  
  
**[点赞+分享****+关注]**  
  
