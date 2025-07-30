#  Apache 修复 Tomcat Web 服务器中的远程代码执行绕过问题   
胡金鱼  嘶吼专业版   2024-12-26 18:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Apache 发布了一个安全更新，解决了 Tomcat Web 服务器中的一个重要漏洞，该漏洞可能导致攻击者实现远程代码执行。  
  
Apache Tomcat 是一种开源 Web 服务器和 Servlet 容器，广泛用于部署和运行基于 Java 的 Web 应用程序。它为 Java Servlet、JavaServer Pages (JSP) 和 Java WebSocket 技术提供运行时环境。  
  
该产品深受运行自定义 Web 应用程序的大型企业和依赖 Java 提供后端服务的 SaaS 提供商的欢迎。云和托管服务集成了 Tomcat 来进行应用程序托管，软件开发人员使用它来构建、测试和部署 Web 应用程序。  
  
新版本中修复的漏洞被追踪为 CVE-2024-56337，并解决了 CVE-2024-50379 的不完整缓解措施，这是一个关键的远程代码执行 (RCE)，供应商已于 12 月 17 日发布了补丁。  
  
人们意识到应用 CVE-2024-50379 的更新不足以保护系统，并决定发布 CVE-2024-56337强调手动操作的必要性。  
  
这两个问题本质上是完全相同的漏洞，但决定使用新的 CVE ID 是为了提高受影响系统管理员的认识。该安全问题是一个检查时间使用时间 (TOCTOU) 竞争条件漏洞，该漏洞会影响启用默认 Servlet 写入（“只读”初始化参数设置为 false）并在不区分大小写的文件系统上运行的系统。  
  
该问题影响 Apache Tomcat 11.0.0-M1 至 11.0.1、10.1.0-M1 至 10.1.33 以及 9.0.0.M1 至 9.0.97。用户应升级到最新的 Tomcat 版本：11.0.2、10.1.34 和 9.0.98。  
  
解决该问题需要采取额外的步骤，根据所使用的 Java 版本，除了升级之外，用户还需要执行以下操作：  
  
**·**对于 Java 8 或 11，建议将系统属性“sun.io.useCanonCaches”设置为“false”（默认值：true）。  
  
**·**对于 Java 17，请确保“sun.io.useCanonCaches”（如果设置）配置为 false（默认值：false）。  
  
**·**对于 Java 21 及更高版本，无需配置。该属性和有问题的缓存已被删除。  
  
Apache 团队分享了即将推出的 Tomcat 版本（11.0.3、10.1.35 和 9.0.99）中的安全增强计划。  
  
具体来说，Tomcat 将在不区分大小写的文件系统上启用默认 servlet 的写访问权限之前检查“sun.io.useCanonCaches”设置是否正确。  
并在可能的情况下将“sun.io.useCanonCaches”默认为 false。  
这些更改旨在自动实施更安全的配置，并降低 CVE-2024-50379 和 CVE-2024-56337 被利用的风险。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/apache-fixes-remote-code-execution-bypass-in-tomcat-web-server/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CrooYeroY7OqzCYW4fiag1S27gCGZpN26xOSNI0cBibR1bB7tpiaXRZOCgy1mgDO38UWqiaH01mHDtA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28CrooYeroY7OqzCYW4fiag1ibjH5ID4JQ0oAl3wZKf7TJ5icxWejV6yyhric6Np5h1TiaWNUUEhQnSspg/640?wx_fmt=png&from=appmsg "")  
  
  
