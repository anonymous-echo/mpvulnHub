#  漏洞预警 | Eking管理易任意文件上传漏洞   
浅安  浅安安全   2024-12-04 00:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
EKing管理易是广州易凯软件技术有限公司专为广告制品制作企业开发的一款管理软件产品。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVn7crQmzAeKozKoN0V6kYGEremUN4Tc8cFzBEz0SCAibpxuib8xyGYJ7ianbR5f7Dlrxlh8QNOw1tyQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**漏洞类型：**  
任意文件上传  
  
**影响：**  
上传恶意文件****  
  
**简述：**  
EKing管理易的/Base64Upload.ihtm接口处存在任意文件上传漏洞，未经身份验证的远程攻击者可利用此漏洞上传任意文件，在服务器端任意执行代码获取服务器权限，进而控制整个web服务器。  
  
**0x04 影响版本**  
- EKing管理易  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.ekingcn.com/  
  
  
  
