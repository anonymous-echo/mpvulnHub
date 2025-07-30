#  漏洞预警 | SonicWall SMA100 SSL-VPN缓冲区溢出漏洞   
浅安  浅安安全   2024-12-17 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-45318  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
SonicWall是全球知名的网络安全解决方案提供商，专注于防火墙、VPN、入侵防御等领域，其客户覆盖企业、服务提供商、电子商务、政府和教育机构等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUDj240kvN5PDDJx6Ra1pPOJHMBOTBFotl6hhTTT1ps5wtM9ruaYBNU3icgXTDy2MawiaAFE87mPRbA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-45318**  
  
**漏洞类型：**  
缓冲区溢出  
  
**影响：**  
任意代码执行  
  
****  
  
**简述：**  
SonicWall SMA100 SSL-VPN中存在基于栈的缓冲区溢出漏洞，该漏洞存在于SonicWall SMA100 SSL-VPN Web管理界面中，未经身份验证的远程攻击者可利用该漏洞触发缓冲区溢出并可能导致任意代码执行。  
  
**0x04 影响版本**  
- SMA 100系列 <= 10.2.1.13-72sv  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.sonicwall.com/  
  
  
  
