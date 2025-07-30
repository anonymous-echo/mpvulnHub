#  漏洞预警 | Apache Linkis任意文件读取漏洞   
浅安  浅安安全   2025-01-20 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Apache Linkis是面向大数据和人工智能应用的开源治理平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXytBrmBlNoib9nlAny0SqxfltL56kGojY2MDtBgD0ragicDkYduT1rEJQqWB4tGlnGYPZTicZJC4WjA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
Apache Linkis存在文件读取漏洞，由于其数据源管理模块未对传入的JDBC URL中的参数做限制，具备数据源管理权限的攻击者可以在JDBC URL写入allowloadlocalinfile、allowurlinlocalinfile、allowloadlocalinfileinpath、autodeserialize参数来读取文件。  
  
**0x04 影响版本**  
- 1.5.0 <= Apache Linkis < 1.7.0  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://linkis.apache.org/  
  
  
  
