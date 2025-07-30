#  漏洞预警 | SitecoreCMS任意文件读取漏洞   
浅安  浅安安全   2024-12-24 00:01  
  
**0x00 漏洞编号**  
- # CVE-2024-46938  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Sitecore是一个全球领先的数字体验管理平台，以增强的内容管理系统和数字营销功能而闻名。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXnntOIXgZRibKgBXy9W9U6PQOj8YicRTZuohPJGBicKEwMr6NYic9mIDa3mQyypxhugj5FvFSd6zOZdQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-46938**  
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
Sitecore的/-/speak/v1/bundles/bundle.js接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取服务器大量敏感信息。  
  
**0x04 影响版本**  
- Sitecore <= 10.4  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.sitecore.com/  
  
  
  
