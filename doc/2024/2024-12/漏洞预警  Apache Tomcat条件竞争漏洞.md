#  漏洞预警 | Apache Tomcat条件竞争漏洞   
浅安  浅安安全   2024-12-23 00:02  
  
**0x00 漏洞编号**  
- CVE-2024-50379  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Tomcat是一个流行的开源Web服务器和Java Servlet容器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU8iaTUOG2Yp65MtC7pXugJBicOLQo4hnzZ2K8RKZzN0pdaGyE5ArTbCv1JVTQQG35XcQYAOsUUcicIg/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-50379**  
  
**漏洞类型：**  
条件竞争  
  
**影响：**  
代码执行  
  
**简述：**  
Apache Tomcat中JSP编译期间存在检查时间使用TOCTOU竞争条件漏洞，当Apache Tomcat的默认servlet被配置为允许写入，在不区分大小写的文件系统上，当对同一文件进行并发读取和上传时，可能绕过Tomcat的大小写敏感性检查，导致上传的文件被错误地当作JSP文件处理，从而导致远程代码执行。  
  
**0x04 影响版本**  
- 11.0.0-M1 <= Apache Tomcat <= 11.0.1  
  
- 10.1.0-M1 <= Apache Tomcat <= 10.1.33  
  
- 9.0.0.M1 <= Apache Tomcat <= 9.0.97  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://tomcat.apache.org/  
  
  
  
