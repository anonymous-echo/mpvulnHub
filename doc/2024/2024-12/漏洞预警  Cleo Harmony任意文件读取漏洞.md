#  漏洞预警 | Cleo Harmony任意文件读取漏洞   
浅安  浅安安全   2024-12-21 00:02  
  
**0x00 漏洞编号**  
- # CVE-2024-50623  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Cleo Harmony是Cleo公司推出的一款用于B2B集成和数据交换的解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVJ8icaQWhuBjnPFoDcBViaUCfSI3iaTWz2YGxK58pazYWNekicXriam6tCkDkXBaDxl6tiaV2wCbFCamLA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-50623**  
  
**漏洞类型：**  
任意文件读取****  
  
**影响：**  
  
获取敏感信息  
  
  
****  
  
**简述：**  
Cleo Harmony的/Synchronization接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- Cleo Harmony < 5.8.0.21  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.cleo.com/  
  
  
  
