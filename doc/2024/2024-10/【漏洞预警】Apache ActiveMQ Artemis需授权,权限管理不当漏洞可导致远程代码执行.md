#  【漏洞预警】Apache ActiveMQ Artemis需授权,权限管理不当漏洞可导致远程代码执行   
cexlife  飓风网络安全   2024-10-15 22:04  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02kGdfTMbyScIb2h8FA5zZ8hpEeelQ0JRuJ7Opsicz5BYGib33Ricia8qlPNtGoxArISmSUmtewknB6bQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
ApacheActiveMQArtemis发布安全公告,公开了一个Apache ActiveMQArtemis中的权限管理不当漏洞,该漏洞是由于Apache ActiveMQ Artemis通过MBean提供对诊断信息和控制的访问,这些信息和控制也可以通过经过身份验证的Jolokia端点进行访问,在2.29.0版本之前,这也包括Log4J2 MBean,通过Log4J2 MBean可能允许经过认证的攻击者向文件系统写入任意文件,在服务器上执行任意代码。  
  
**修复建议:正式防护方案:**厂商已发布补丁修复漏洞,用户请尽快更新至安全版本:建议用户立即升级到2.29.0或更高版本,以修复此问题。**下载链接:**https://activemq.apache.org/downloads.html)。完成升级后,建议重启服务以确保更改生效。与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。**参考链接:**https://lists.apache.org/thread/63b78shqz312phsx7v1ryr7jv7bprg58  
  
