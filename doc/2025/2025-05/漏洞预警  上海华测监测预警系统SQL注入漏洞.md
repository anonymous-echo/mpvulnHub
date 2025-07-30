#  漏洞预警 | 上海华测监测预警系统SQL注入漏洞   
浅安  浅安安全   2025-05-14 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
上海华测监测预警系统是一套科学完善的地质灾害监测预警平台，实现了地质灾害防治管理的科学化、信息化、标准化和可视化。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVLefeEu6HZ5s5toFe49m7cuYnbMjqnVUkjtc60seqVWt3TC9t9Lx7yeR1DrGCLVZlv9ibibPt9ia5jQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
上海华测监测预警系统在2.2中存在SQL注入漏洞，未经授权的攻击者可能通过  
/Web/SysManage/sysGroupEdit.aspx文件的ID参数进行SQL注入，从而获取数据库中的敏感信息或进行命令执行控制服务器。  
  
**0x04 影响版本**  
- 上海华测监测预警系统 2.2  
  
**0x05****POC状态**  
- **未公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.huace.cn/  
  
  
  
