#  【漏洞情报】Vmware Spring Security访问控制不当漏洞   
cexlife  飓风网络安全   2024-10-31 22:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01KdlKovDEZkJfACVDBXp7tU9dic4HRKQibmIfnBGoPAoAsx0hzBYpaAGIwGGO7PO7LBxVUKwnt31RQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**VMware发布安全公告,其中公开了一个Spring Security中的访问控制不当漏洞,在某些情况下Spring WebFlux应用程序在静态资源上使用Spring Security授权规则时可以绕过对静态资源具有Spring Security授权规则的访问控制。**修复建议:正式防护方案:**厂商已发布补丁修复漏洞,建议联系厂商获取相关支持尽快更新至安全版本。Spring Security >= 5.7.13Spring Security >= 5.8.15Spring Security >= 6.0.13Spring Security >= 6.1.11Spring Security >= 6.2.7Spring Security >= 6.3.4较旧的、不受支持的版本也会受到影响，与此同时，请做好资产自查以及预防工作，以免遭受黑客攻击。**参考链接:**https://spring.io/security/cve-2024-38821  
  
