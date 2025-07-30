#  漏洞预警 | Mitel MiCollab身份验证绕过漏洞   
浅安  浅安安全   2024-12-17 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-41713  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Mitel MiCollab是一个企业协作平台，它将各种通信工具整合到一个应用程序中，提供语音和视频通话、消息传递、状态信息、音频会议、移动支持和团队协作功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUDj240kvN5PDDJx6Ra1pPOibIpZGBLvRr1Wu1Tu92qI0UFe3tdaCObUicNLsjgAr79P47qL3B3V9ibQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-41713**  
  
**漏洞类型：**  
身份验证绕过  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
Mitel MiCollab的NuPoint统一消息组件中存在身份验证绕过漏洞，由于输入验证不足，未经身份验证的远程攻击者可利用该漏洞执行路径遍历攻击，成功利用可能导致未授权访问、破坏或删除用户的数据和系统配置。  
  
**0x04 影响版本**  
- Mitel MiCollab <= 9.8 SP1 FP2 (9.8.1.201)  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.mitel.com/  
  
  
  
