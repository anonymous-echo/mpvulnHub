#  漏洞预警 | Zyxel ZLD防火墙路径遍历漏洞   
浅安  浅安安全   2024-12-09 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-11667  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Zyxel是国际知名的网络宽带系统及解决方案供应商。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SX0RNkRpMXK8kQK9DpY3cyPmwPldZlKw34EXoOl7bBiazLqg6ImRDD4XejebOZOV07PmLsAn2sVNRg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-11667**  
  
**漏洞类型：**  
目录遍历****  
  
**影响：**  
获取敏感信息  
  
**简述：**  
Zyxel ZLD防火墙的Web管理界面中存在目录遍历漏洞，未经身份验证的远程攻击者可通过恶意设计的URL来访问系统的文件目录，从而下载或上传文件，成功利用该漏洞可能导致未授权访问敏感文件，造成敏感信息泄露。  
  
**0x04 影响版本**  
- V5.00 <= Zyxel ATP系列固件 <= V5.38  
  
- V5.00 <= Zyxel USG FLEX系列固件 <= V5.38  
  
- V5.10 <= Zyxel USG FLEX 50(W)系列固件 <= V5.38  
  
- V5.10 <= Zyxel USG20(W)-VPN系列固件 <= V5.38  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zyxel.cn/  
  
  
  
