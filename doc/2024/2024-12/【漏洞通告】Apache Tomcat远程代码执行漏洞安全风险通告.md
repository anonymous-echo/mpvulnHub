#  【漏洞通告】Apache Tomcat远程代码执行漏洞安全风险通告   
 嘉诚安全   2024-12-18 07:32  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Apache官方发布安全公告，修复了一个Apache Tomcat远程代码执行漏洞，漏洞编号为：  
CVE-2024-50379。  
  
  
Apache Tomcat是一个开源的Java Servlet容器，广泛用于运行Java Web应用程序。它实现了Java Servlet和JavaServer Pages (JSP) 技术，提供了一个运行环境来处理HTTP请求、生成动态网页，并支持WebSocket通信。Tomcat以其稳定性、灵活性和易用性而受到开发者的青睐，是开发和部署Java Web应用的重要工具之一。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，且  
**PoC已公开**  
。该漏洞是由于Tomcat在验证文件路径时存在缺陷，如果readonly参数被设置为false（这是一个非标准配置），并且服务器允许通过PUT方法上传文件，那么攻击者就可以上传含有恶意JSP代码的文件。通过不断地发送请求，攻击者可以利用条件竞争，使得Tomcat解析并执行这些恶意文件，从而实现远程代码执行。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
11.0.0-M1 <= Apache Tomcat < 11.0.2  
  
10.1.0-M1 <= Apache Tomcat < 10.1.34  
  
9.0.0.M1 <= Apache Tomcat < 9.0.98  
  
  
**处置建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，受影响用户可升级到Apache Tomcat 11.0.2、10.1.34、9.0.98版本，下载链接：  
  
11版本：https://tomcat.apache.org/download-11.cgi  
  
10版本：https://tomcat.apache.org/download-10.cgi  
  
9版本：https://tomcat.apache.org/download-90.cgi  
  
参考链接：  
  
https://lists.apache.org/thread/y6lj6q1xnp822g6ro70tn19sgtjmr80r  
  
http://www.openwall.com/lists/oss-security/2024/12/17/4  
  
https://github.com/apache/tomcat/commit/05ddeeaa54df1e2dc427d0164bedd6b79f78d81f  
  
https://github.com/apache/tomcat/commit/43b507ebac9d268b1ea3d908e296cc6e46795c00  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
