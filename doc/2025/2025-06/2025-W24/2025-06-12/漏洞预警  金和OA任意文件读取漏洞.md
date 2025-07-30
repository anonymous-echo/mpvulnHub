#  漏洞预警 | 金和OA任意文件读取漏洞  
浅安  浅安安全   2025-06-12 00:01  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 中危  
  
**0x02 漏洞概述**  
  
金和网络是专业信息化服务商，为城市监管部门提供了互联网+监管解决方案，为企事业单位提供组织协同OA系统开发平台、电子政务一体化平台、智慧电商平台等服务。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXOhrIicAqN0TULjm0J7IN5y6sLyKp9DrQOTW803iaDNmGpf9bm43iaggj4WUjsIpZLnLhdic1mhbExTQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**0x03 漏洞详情**  
###   
  
**漏洞类型：**  
任意文件读取  
  
**影响：**  
获取敏感信息  
  
****  
  
**简述：**  
金和JC6协同管理平台的  
/jc6/servlet/WebBill和/jc6/servlet/PathFile?GetUrl  
接口存在任意文件读取漏洞，攻击者可利用该漏洞获取服务器敏感信息。  
  
**0x04 影响版本**  
- 金和OA C6  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
http://www.jinher.com/  
  
  
  
