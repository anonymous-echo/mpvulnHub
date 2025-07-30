#  漏洞预警 | Oracle Scripting iSurvey模块远程代码执行漏洞   
浅安  浅安安全   2025-04-19 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-30727  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Oracle Scripting是Oracle E-Business Suite中的一个组件，用于创建和管理在线调查、表单及动态脚本。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVjdb8W7T5YIrddGeQMLUBTXbxfZXlfOKXWTLDDbHJlEslX5e6xKhdokgiccSG2ibPY1uNib5wFzVicEg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-30727**  
  
**漏洞类型：**  
代码执行  
  
**影响：**  
执行任意代码  
  
  
  
**简述：**  
Oracle Scripting iSurvey模块存在远程代码执行漏洞，未认证的攻击者可通过HTTP网络访问远程利用该漏洞，从而导致Oracle Scripting被完全攻陷。  
  
**0x04 影响版本**  
- 12.2.3 <= Oracle E-Business Suite <= 12.2.14  
  
**0x05****POC状态**  
- 未公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.oracle.com/cn/  
  
  
  
