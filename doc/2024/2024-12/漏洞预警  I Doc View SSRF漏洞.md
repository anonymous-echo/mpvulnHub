#  漏洞预警 | I Doc View SSRF漏洞   
浅安  浅安安全   2024-12-14 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
I Doc View在线文档预览系统是一套用于在Web环境中展示和预览各种文档类型的系统，如文本文档、电子表格、演示文稿、PDF文件等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVudq6gjlAvIjqPJVMrq3LzracWBvEPicfiaAfzibKSiaPCVzGAyV2vjwvHFR6ly4AUXrULDpnicEotfoA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SSRF  
  
**影响：**  
  
获取  
敏感信息  
  
**简述：**  
I Doc View在线文档预览的/view/url接口存在SSRF漏洞，未授权的攻击者可使用file协议读取系统敏感文件。  
  
**0x04 影响版本**  
- I Doc View  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.idocv.com/  
  
  
  
