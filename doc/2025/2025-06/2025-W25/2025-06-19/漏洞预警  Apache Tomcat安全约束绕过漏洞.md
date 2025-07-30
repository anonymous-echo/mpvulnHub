> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493446&idx=1&sn=bb7af1bdae0d924f2df258a74cea48e5

#  漏洞预警 | Apache Tomcat安全约束绕过漏洞  
浅安  浅安安全   2025-06-19 00:00  
  
**0x00 漏洞编号**  
- CVE-2025-49125  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Tomcat是一个流行的开源Web服务器和Java Servlet容器。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWJJsicexOeGePbC9kyVvapu9wiclKfBZRwyWZSn0HheHxmVzMf32MBvk9bjyvt55C0RxejMwSKxanQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-49125**  
  
**漏洞类型：**  
安全约束绕过  
  
**影响：**  
越权访问  
  
**简述：**  
Apache Tomcat中存在安全约束绕过漏洞，当PreResources或PostResources被挂载在Web应用根目录之外时，攻击者可能通过非预期路径访问这些资源，从而绕过原本应保护这些资源的安全约束。  
  
**0x04 影响版本**  
- 11.0.0-M1 <= Apache Tomcat <= 11.0.7  
  
- 10.1.0-M1 <= Apache Tomcat <= 10.1.41  
  
- 9.0.0-M1 <= Apache Tomcat <= 9.0.105  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://tomcat.apache.org/  
  
  
  
