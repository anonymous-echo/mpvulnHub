#  漏洞预警 | Fortinet FortiOS & FortiProxy越界写入漏洞   
浅安  浅安安全   2024-03-13 08:00  
  
**0x00 漏洞编号**  
- # CVE-2024-21762  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Fortinet FortiOS是美国飞塔公司的一套专用于FortiGate网络安全平台上的安全操作系统。该系统为用户提供防火墙、防病毒、IPSec/SSLVPN、Web内容过滤和反垃圾邮件等多种安全功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWUiavUteqGxMfL5qEdJ8rpv5cVgicLJocw3Yf4SiajUeqHgyGI6WZEWfsKvr4mRJyI3m6QWR8mXpvPw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**CVE-2024-21762**  
  
**漏洞类型：**  
拒绝服务  
  
**影响：**  
服务崩溃  
  
**简述：**  
Fortinet FortiOS和FortiProxy多个版本在SSL VPN组件中存在越界写入漏洞，可能导致未经身份验证的远程威胁者通过特制HTTP请求执行任意命令或代码。  
###   
  
**0x04 影响版本**  
- 7.4.0 <= FortiOS <= 7.4.2  
  
- 7.2.0 <= FortiOS <= 7.2.6  
  
- 7.0.0 <= FortiOS <= 7.0.13  
  
- 6.4.0 <= FortiOS <= 6.4.14  
  
- 6.2.0 <= FortiOS <= 6.2.15  
  
- 6.0.0 <= FortiOS <= 6.0.17  
  
- 7.4.0 <= FortiProxy <= 7.4.2  
  
- 7.2.0 <= FortiProxy <= 7.2.8  
  
- 7.0.0 <= FortiProxy <= 7.0.14  
  
- 2.0.0 <= FortiProxy <= 2.0.13  
  
- FortiProxy 1.2所有版本  
  
- FortiProxy 1.1所有版本  
  
- FortiProxy 1.0所有版本  
  
**0x05****POC**  
  
https://github.com/c0d3b3af/CVE-2024-21762-Exploit  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.fortinet.com  
  
  
  
