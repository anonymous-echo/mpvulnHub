#  漏洞预警 | UNA CMS PHP对象注入漏洞   
浅安  浅安安全   2025-04-17 00:00  
  
**0x00 漏洞编号**  
- # CVE-2025-32101  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
UNA CMS是一款基于PHP和MySQL的开源内容管理系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUkBxorpcHHaLhN3CRSfmcaM9oYMIQGCXT2NKt9SRdYuZWrhz19HaHoyf70ciaF4CzUCvdNKgNicSkA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2025-32101**  
  
**漏洞类型：**  
对象注入  
  
**影响：**  
任意文件访问或修改、信息泄露或代码执行  
  
**简述：**  
UNA CMS的/menu.php接口存在PHP对象注入漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- UNA CMS 14.0.0-RC  
  
**0x05 PO状态**  
- **已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://una.sh/  
  
  
  
