#  漏洞预警 | 用友U8Cloud任意文件读取漏洞   
浅安  浅安安全   2025-05-28 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jsiaZ70u94EB6R9eOgsPln1PWpP3MSljJmZEwZYep2iakwjxN7DsbXlfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友U8Cloud的/service/FileManageServlet接口存在任意文件读取漏洞，未经身份验证的攻击者可以通过该漏洞读取服务器任意文件，从而获取大量敏感信息。  
  
**0x04 影响版本**  
- 用友U8Cloud  
  
**0x05****POC状态**  
- 已公开  
  
****  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
