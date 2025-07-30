#  漏洞预警 | 全程云OA SQL注入漏洞   
浅安  浅安安全   2024-11-20 00:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
全程云OA一体化协同办公软件是全程云出品企业一体化管理软件，为企业内部协同办公管理提供了高效的软件解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUP55gXJX9UnHyoOUYLPM7fI1iaLlgBxHvanq736GZjjRBBPSQ9E4kIvrWib1ia6DZI0rsAWPgYNbTNw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
全程云OA的/OA/PES/QCPES.asmx接口处存在多处SQL注入漏洞，未经身份验证的攻击者可以通过该漏洞拼接执行任意SQL语句，从而获取数据库敏感信息。  
###   
  
**0x04 影响版本**  
- 全程云OA  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.eqccd.com/  
  
  
  
