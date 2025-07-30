> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493681&idx=1&sn=9523c6d0eda530b7c5ebdd3ac944351d

#  漏洞预警 | 畅捷通T+ SQL注入漏洞  
浅安  浅安安全   2025-07-10 23:50  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
畅捷通T+是一款主要针对中小型工贸和商贸企业的财务业务一体化应用，融入了社交化、移动化、物联网、电子商务、互联网信息订阅等元素。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7stTqD182SUILDwZiaCjMtWRej8GVJEGRaG5pxp8u8ar4nlYEmA0QuictibrSRCq237G4T3Ma9yibCerGmAj2oBaVg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
畅捷通T+的/tplus/ajaxpro/Ufida.T.SM.UIP.Tool.AccountClearControler,Ufida.T.SM.UIP.ashx接口存在SQL注入漏洞  
，未经身份验证的攻击者可以利用SQL注入漏洞获取数据库中的信息。  
  
**0x04 影响版本**  
- 畅捷通T+  
  
**0x05****POC状态**  
- **已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.chanjet.com/  
  
  
  
