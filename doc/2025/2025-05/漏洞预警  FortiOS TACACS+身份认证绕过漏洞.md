#  漏洞预警 | FortiOS TACACS+身份认证绕过漏洞   
浅安  浅安安全   2025-05-20 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-22252  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
FortiOS是Fortinet提供的操作系统，用于其安全设备。FortiProxy是FortiOS的一个组件，主要用于代理服务，提供反向代理、Web应用防火墙等功能，帮助企业保护其Web应用免受攻击并优化网络流量。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU1ibQ8sYR4TvrgDEIO9AXibfKFIopibSrR0Mp0me9xDjXtCzSPic2IVCOY1hkEeBBglLO9zQyicL3N8BA/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-22252**  
  
**漏洞类型：**  
身份验证不当  
  
**影响：**  
越权操作  
  
**简述：**  
FortiOS、FortiProxy和FortiSwitchManager中的TACACS+存在身份认证绕过漏洞。当TACACS+配置为使用远程TACACS+服务器进行身份验证，且该服务器使用ASCII认证时，攻击者可以绕过正常的认证机制，伪装成有效管理员，获得设备的管理员权限。  
  
**0x04 影响版本**  
- FortiOS 7.6.0  
  
- 7.4.4 <=  FortiOS <=  7.4.6  
  
- 7.6.0 <=  FortiProxy <= 7.6.1  
  
- FortiSwitchManager 7.2.5  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.fortinet.com/  
  
  
  
