#  漏洞预警 | Fortinet FortiOS与FortiProxy身份验证绕过漏洞   
浅安  浅安安全   2025-01-21 00:02  
  
**0x00 漏洞编号**  
- # CVE-2024-55591  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
FortiOS是Fortinet提供的操作系统，用于其安全设备。FortiProxy是FortiOS的一个组件，主要用于代理服务，提供反向代理、Web应用防火墙等功能，帮助企业保护其Web应用免受攻击并优化网络流量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SU1ibQ8sYR4TvrgDEIO9AXibfKFIopibSrR0Mp0me9xDjXtCzSPic2IVCOY1hkEeBBglLO9zQyicL3N8BA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-55591**  
  
**漏洞类型：**  
身份验证不当  
  
**影响：**  
越权操作  
  
**简述：**  
FortiOS和FortiProxy存在身份验证绕过漏洞，攻击者可通过精心构造的请求，利用Node.js WebSocket模块，绕过身份验证并获取超级管理员权限。  
  
**0x04 影响版本**  
- 7.0.0 <= FortiOS 7.0 <= 7.0.16  
  
- 7.2.0 <= FortiProxy 7.2 <= 7.2.12  
  
- 7.0.0 <= FortiProxy 7.0 <= 7.0.19  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.fortinet.com/  
  
  
  
