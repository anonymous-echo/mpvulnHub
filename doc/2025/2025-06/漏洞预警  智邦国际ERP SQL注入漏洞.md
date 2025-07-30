#  漏洞预警 | 智邦国际ERP SQL注入漏洞   
浅安  浅安安全   2025-06-06 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
智邦一体化ERP将企业物流、资金流、信息流等所有资源整合在一起，对销售、采购、生产、成本、库存、分销、运输、财务、人力资源进行规划，在一套系统内解决企业所有的管理问题。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVLNvdLkO9wEiaL55HVyibFlmC5smsicdRk7GBTMf9SoUJCOgszZx5NqbV6LPB2IMrwYoIYz5v0ibpSHg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
窃取敏感信息  
  
**简述：**  
智邦国际ERP的  
/SYSN/json/pcclient/RecordPrint.ashx接口存在SQL注入漏洞，攻击者可以通过该漏洞执行任意SQL语句，在某些情况下，可以读入或写出文件，或者在底层操作系统上执行shell命令。  
  
**0x04 影响版本**  
- 智邦国际ERP  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.zbintel.com/  
  
  
  
