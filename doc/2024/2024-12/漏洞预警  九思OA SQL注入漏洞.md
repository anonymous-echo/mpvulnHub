#  漏洞预警 | 九思OA SQL注入漏洞   
浅安  浅安安全   2024-12-07 00:30  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
九思OA办公自动化系统平台基于开发JAVA语言开发，封装了大量接口、构件，以多维门户形式展现，OA系统支持各种部署模式、各种操作系统、各种数据库和中间件，并具备完备的配置体系、接口体系和插件体系，支持未来的不断扩展。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUa31NzHTaaCIE7AEkrcLPY19woVFm92BcBkqLZMpqoPl9Rc4PBnWbibQHDRRaevxJNIKjxIWLdLlw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
九思OA的/jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 九思OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.jiusi.net/  
  
  
  
