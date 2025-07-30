#  Apache基金会修复了一个严重的Tomcat漏洞   
鹏鹏同学  黑猫安全   2024-12-24 23:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce8UHDVXKZXwGxvbq6zQx2Q6N1icIXLq1HDjmKPYSR7bvhmpv5wCY8t1Q66RLFOd5u2iaUKTWqrObm9Q/640?wx_fmt=png&from=appmsg "")  
  
Apache软件基金会(ASF)修复了其Tomcat服务器软件中的一个重要漏洞，编号为CVE-2024-56337。研究人员警告说，在特定条件下，利用此漏洞可能导致远程代码执行。Apache Tomcat是Java Servlet、JavaServer Pages (JSP)、Jakarta表达式语言和WebSocket技术的开源实现。它由Apache软件基金会开发，被广泛用作运行基于Java的Web应用程序的Web服务器和Servlet容器。  
  
该漏洞是Apache Tomcat中的一个TOCTOU竞争条件问题，影响版本11.0.0-M1到11.0.1、10.1.0-M1到10.1.33以及9.0.0.M1到9.0.97。此漏洞是由于CVE-2024-50379 (CVSS评分：9.8)的缓解措施不完整造成的。“在不区分大小写的文件系统上运行Tomcat且启用了默认servlet写入（readonly初始化参数设置为非默认值false）的用户可能需要额外的配置才能完全缓解CVE-2024-50379，具体取决于他们与Tomcat一起使用的Java版本。”安全公告中写道。  
- CVE-2024-50379的缓解措施不完整，需要根据Java版本进行配置：  
  
- Java 8/11：将sun.io.useCanonCaches设置为false（默认为true）。  
  
- Java 17：确保sun.io.useCanonCaches为false（默认为false）。  
  
- Java 21+：无需配置（属性已移除）。  
  
从Tomcat 11.0.3、10.1.35和9.0.99开始，检查将强制执行sun.io.useCanonCaches的正确配置。  
  
安全研究人员Nacl、WHOAMI、Yemoli和Ruozhi发现了这两个漏洞。KnownSec 404团队的Dawu和Sunflower独立报告了此漏洞，并提供了详细的概念验证。  
  
  
