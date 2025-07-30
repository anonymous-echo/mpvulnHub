> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NDY2OTU4Nw==&mid=2247521903&idx=1&sn=1fd7e0366f5859e4c0707a8c6325bcaa

#  一键触发漏洞：Oracle云代码编辑器RCE漏洞允许攻击者上传恶意文件  
 船山信安   2025-07-18 16:01  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNP2nmp9DzYCBqMBwiaILJORPpWpck9OhB0U9Jdf2509dCDYkZricPPuxsQ1gIwAscPnDLbQd30fKMA/640?wx_fmt=jpeg&from=appmsg "")  
  
Oracle云基础设施(OCI)代码编辑器中存在一个严重的远程代码执行(RCE)漏洞，攻击者只需点击一次即可静默劫持受害者的Cloud Shell环境。该漏洞目前已修复，影响了代码编辑器的集成服务，包括资源管理器、函数服务和数据科学服务，揭示了看似隔离的云开发工具如何成为攻击媒介。  
## 核心发现  
1. Oracle云代码编辑器的文件上传功能缺乏CSRF防护，允许通过点击触发恶意文件上传  
  
1. 漏洞导致远程代码执行，可能危及集成的OCI服务  
  
1. Oracle已添加强制X-CSRF-Token标头来防御跨站攻击  
  
## 漏洞技术分析  
  
该漏洞源于Oracle代码编辑器与Cloud Shell的深度集成，两者共享相同的底层文件系统和用户会话上下文。虽然这种紧密耦合旨在提供无缝的开发体验，却意外创造了攻击面。  
  
安全公司Tenable的研究始于一个简单问题：如果开发者能通过代码编辑器轻松上传文件，攻击者是否也能做到？调查发现代码编辑器的/file-upload端点缺乏跨站请求伪造(CSRF)防护，而Cloud Shell的上传机制则具备完善防护。  
  
![漏洞利用示意图](https://mmbiz.qpic.cn/mmbiz_gif/7nIrJAgaibicNP2nmp9DzYCBqMBwiaILJORFFaQXxPWGJNYyvEHo4vc9jia4oMRthHO7PfkKIia26bnXZSqG7VWYLWA/640?wx_fmt=gif&from=appmsg "")  
  
漏洞核心在于Cloud Shell路由器(router.cloudshell.us-ashburn-1.oci.oraclecloud.com)，该组件接收包含multipart/form-data负载的HTTP POST请求。路由器使用的CS-ProxyChallenge cookie配置了SameSite=None属性，对认证用户的跨站请求毫无防护。  
## 攻击实现方式  
  
攻击者可创建恶意HTML页面，当认证的OCI用户访问时，页面会自动向其Cloud Shell环境上传恶意文件。研究人员演示了攻击者如何覆写.bashrc文件建立反向shell，获取Cloud Shell的交互式访问权限，并利用受害者凭证通过OCI CLI在OCI服务间横向移动。  
  
![攻击请求示例](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicNP2nmp9DzYCBqMBwiaILJORU4CNsL3QDkibKOEJPevdRq2A7yLlZzV3ic674ibKuo7Fn3xhmialkEyQ8g/640?wx_fmt=jpeg&from=appmsg "")  
## 防护措施  
  
Oracle通过实施额外安全措施修复了该漏洞，要求所有相关请求必须包含值为csrf-value的自定义HTTP头x-csrf-token。由于浏览器无法在跨域请求中自动包含自定义头（除非配置了CORS），这一变更有效缓解了CSRF攻击。  
  
该漏洞的影响不仅限于Cloud Shell，还波及代码编辑器的集成服务。由于这些服务运行在共享文件系统上，恶意负载可能危及资源管理器工作区、函数部署和数据科学环境，在OCI开发者工具套件中形成了多层面的威胁。此事件凸显了云服务集成中固有的安全挑战——便利性功能可能无意中扩大了攻击面。  
  
  
转载来源：【  
https://www.freebuf.com/articles/web/440069.html】  
  
