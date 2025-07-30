#  漏洞预警 | 泛微E-Bridge SQL注入漏洞   
浅安  浅安安全   2025-01-02 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
泛微E-Bridge是上海泛微公司在"互联网+"的背景下研发的一款用于桥接互联网开放资源与企业信息化系统的系统集成中间件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUrJBibTRVnu4S9micz4sX1rDm6wgINB5BOuEZ1swwx74zHow6XXph4ShdJXYO1oVtoozO5uSvoW9dQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
泛微E-Bridge的/taste/checkMobile接口存在SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 泛微  
E-Bridge  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.weaver.com.cn/  
  
  
  
