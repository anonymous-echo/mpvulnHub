#  漏洞预警 | 商混ERP系统SQL注入漏洞   
浅安  浅安安全   2024-09-28 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
商混ERP系统是一种针对混凝土行业开发的综合性企业资源规划系统。它集成了生产、销售、采购、财务等各个方面的功能，为混凝土生产企业提供了一个全面、高效的数字化管理平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVK4xQb2ufvg2EXDtgjwmkJ931WLm0SuB1piaUOhggspkfqO6QJyq3icmtIoiaaVGOpuibAOPIYmCDrJQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
  
  
  
**简述：**  
商混ERP系统的/Dispatch/Operater_Action.aspx、/ERP/StockreceiveEdit.aspx和/Dispatch/TaskCarToQueue.aspx接口存在SQL注入漏洞，未经身份验证的远程攻击者可以利用该漏洞获取数据库中的信息。  
###   
  
**0x04 影响版本**  
- 荷花商品混凝土管理软件  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.85info.com/  
  
  
  
