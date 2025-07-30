#  漏洞预警 | 通达OA远程代码执行漏洞   
浅安  浅安安全   2025-05-08 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
通达OA是一款协同办公自动化软件，由北京通达信科科技有限公司自主研发，为各行业不同规模的众多用户提供信息化管理能力。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXoaRemR3mxsuiciaUbPcWn9jh3fRf3kEPOKncTu948nZibfkXCnmJicDzVrQIkk6CS8KDmiaEiab6jMLqw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
通达OA的/general/appbuilder/web/portal/gateway/dologin接口存在远程代码执行漏洞，未经身份验证的攻击者可以通过该漏洞远程执行任意代码，从而控制目标服务器。  
  
**0x04 影响版本**  
- 通达OA  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.tongda2000.com/  
  
  
  
