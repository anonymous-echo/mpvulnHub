#  【漏洞预警】Grafana未授权跨站点脚本攻击XSS&SSRF漏洞   
cexlife  飓风网络安全   2025-05-23 12:25  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00NScK3ia8vibEp9FicmcfYsv8icW4clxAicSMST9qIpJdjGKic6B8zypFzHw4fDicEuWd1BTnFY8OnpUNXA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Grafana发布安全公告修复了2个安全漏洞,其中包括一个跨站点脚本（XSS）漏洞,该漏洞是由客户端路径遍历和开放重定向的结合造成的。这使得攻击者能够将用户重定向到一个托管前端插件的网站该插件将执行任意的JavaScript,如果安装了Grafana图像渲染器插件,则可以利用开放重定向来实现完全读取的SSRF,官方已经发布新版本修复此漏洞,建议受影响用户及时升级到安全版本。  
  
poc:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00NScK3ia8vibEp9FicmcfYsv8ibkU4xRvHsSzawibYjcjKPMSg7BMoibibjZibibVNzmte3YAnwaJk3tUzmdg/640?wx_fmt=png&from=appmsg "")  
  
攻击场景:  
  
攻击者可能通过自定义前端插件将用户重定向到恶意网站,并执行任意 JаvаSсriрt 代码。  
  
影响版本:  
  
11.2<=Grafana Grafana<11.2.9+security-01  
  
11.3<=Grafana Grafana<11.3.6+security-01  
  
11.4<=Grafana Grafana<11.4.4+security-01  
  
11.5<=Grafana Grafana<11.5.4+security-01  
  
11.6<=Grafana Grafana<11.6.1+security-01  
  
12.0<=Grafana Grafana<12.0.0+security-01  
  
修复建议:  
  
针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:  
  
Grafana >= 12.0.0+security-01  
  
Grafana >= 11.6.1+security-01  
  
Grafana >= 11.5.4+security-01  
  
Grafana >= 11.4.4+security-01  
  
Grafana >= 11.3.6+security-01  
  
Grafana >= 11.2.9+security-01  
  
Grafana >= 10.4.18+security-01  
  
下载链接:  
  
https://grafana.com/blog/2025/05/21/grafana-security-release-high-severity-security-fix-for-cve-2025-4123/  
  
安装前请确保备份所有关键数据,并按照官方指南进行操作。安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
  
