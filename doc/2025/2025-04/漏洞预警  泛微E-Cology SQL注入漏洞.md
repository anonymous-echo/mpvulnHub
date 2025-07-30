#  漏洞预警 | 泛微E-Cology SQL注入漏洞   
浅安  浅安安全   2025-04-28 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
泛微协同管理应用平台（e-cology）是一套兼具企业信息门户、知识管理、数据中心、工作流管理、人力资源管理、客户与合作伙伴管理、项目管理、财务管理、资产管理功能的协同商务平台。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUrJBibTRVnu4S9micz4sX1rDm6wgINB5BOuEZ1swwx74zHow6XXph4ShdJXYO1oVtoozO5uSvoW9dQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
泛微E-cology存在SQL注入漏洞，  
由于将用户可控的参数拼接SQL语句，且该接口经过DES加密传输，导致全局WAF失效，造成SQL注入漏洞。攻击者可利用该漏洞向数据库中写入数据，并利用Ole组件导出为Webshell，实现远程代码执行，进而获取服务器权限。  
  
**0x04 影响版本**  
- 泛微e-cology  
 < v10.74  
  
**0x05****POC状态**  
- 未公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.weaver.com.cn/  
  
  
  
