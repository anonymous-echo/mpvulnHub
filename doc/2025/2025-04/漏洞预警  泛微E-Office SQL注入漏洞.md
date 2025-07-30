#  漏洞预警 | 泛微E-Office SQL注入漏洞   
浅安  浅安安全   2025-04-26 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
泛微e-office是泛微旗下的一款标准协同移动办公平台。主要面向中小企业,平台全方位覆盖日常办公场景,可以有效提升组织管理与协同效率。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXdzG6PvYOo48icCguABC2qRrw0e9ZQvIyJQ5BmT1wdYuJb6uf1Wrncfiaob5icVRjM1JAiaEGHgARtqg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
SQL注入  
  
**影响：**  
获取敏感信息  
  
**简述：**  
泛微e-office的  
/general/system/interface/loginedit/word_update.php、/general/workflow/freerunimgflow.php和/general/officeitem/sort/validate_sort.php接口存在SQL注入漏洞，未授权的攻击者可以通过该漏洞拼接恶意SQL语句，从而获取数据库敏感信息。  
  
**0x04 影响版本**  
- 泛微E-Office  
  
**0x05****POC状态**  
- **已公开**  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.e-office.cn/  
  
  
  
