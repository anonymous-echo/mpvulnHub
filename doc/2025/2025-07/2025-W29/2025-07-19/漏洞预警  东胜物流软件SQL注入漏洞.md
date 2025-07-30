> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493785&idx=3&sn=91850abc2376b8b501446d5d75e94086

#  漏洞预警 | 东胜物流软件SQL注入漏洞  
浅安  浅安安全   2025-07-19 00:02  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
东胜物流软件是青岛东胜伟业软件有限公司Q一款集订单管理、仓库管理、运输管理等多种功能于一体的物流管理软件。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVRvHyYp8f2p3TfPSC22Wl0YzOhOKsaiaPgcgBvicBswibknPpYcGyAWtI4Qh30xLcL5kwaH7JKogndg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
东胜物流软件的  
/WorkFlow/WorkFlowGridSource.aspx、  
areaname和isout  
接口存在SQL注入漏洞，攻击者可以通过该漏洞获取数据库敏感信息。  
  
**0x04 影响版本**  
- 东胜物流软件  
   
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.dongshengsoft.com/  
  
  
  
