#  漏洞预警 | 用友U8Cloud XXE漏洞   
浅安  浅安安全   2025-05-16 00:00  
  
**0x00 漏洞编号**  
- # CNVD-2025-06352  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jsiaZ70u94EB6R9eOgsPln1PWpP3MSljJmZEwZYep2iakwjxN7DsbXlfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
CNVD-2025-06352  
  
漏洞类型：  
XXE  
  
**影响：**  
执行  
恶意  
命令  
  
**简述：**  
用友U8cloud的  
/servlet/~uap/nc.merp.bs.maportal.NCPortalServlet接口存在XXE漏洞，未授权的攻击者可以通过该漏洞在xml中构造恶意命令，可能会导致服务器数据泄露以及被远控。  
  
**0x04 影响版本**  
- 用友U8Cloud  
  
**0x05****POC状态已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
