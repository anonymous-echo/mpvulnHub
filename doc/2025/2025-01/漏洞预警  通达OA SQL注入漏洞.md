#  漏洞预警 | 通达OA SQL注入漏洞   
浅安  浅安安全   2025-01-25 00:03  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
通达OA是一款协同办公自动化软件，由北京通达信科科技有限公司自主研发，为各行业不同规模的众多用户提供信息化管理能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jh3fRf3kEPOKncTu948nZibfkXCnmJicDzVrQIkk6CS8KDmiaEiab6jMLqw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
通达OA的/general/workflow/query/get_columns.php和/general/workflow/list/get_columns.php接口存在SQL注入漏洞，攻击者通过漏洞可获取数据库敏感信息。  
  
**0x04 影响版本**  
- 通达OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.tongda2000.com/  
  
  
  
