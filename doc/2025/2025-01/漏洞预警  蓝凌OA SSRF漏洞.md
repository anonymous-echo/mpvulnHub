#  漏洞预警 | 蓝凌OA SSRF漏洞   
浅安  浅安安全   2025-01-02 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
蓝凌OA是由深圳市蓝凌软件股份有限公司开发，是一款针对中小企业的移动化智能办公产品。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVYWeZhgoC2Sr4x2V8oP9xibxVjwkNw7mOPBhXIggJJUEib8yBIKKRDaBp0spKcrjBfxviaCWibA2zic2w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
SSRF  
  
**影响：**  
  
获取敏感信息  
  
**简述：**  
蓝凌OA的/sys/webservice/sysFormMainDataInsystemWebservice、/sys/webservice/sysSynchroGetOrgWebService、/sys/webservice/sysNotifyTodoWebServiceEkpj和/sys/webservice/wechatWebserviceService接口存在SSRF漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件，导致网站处于极度不安全状态。  
  
**0x04 影响版本**  
- 蓝凌OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.landray.com.cn/  
  
  
  
