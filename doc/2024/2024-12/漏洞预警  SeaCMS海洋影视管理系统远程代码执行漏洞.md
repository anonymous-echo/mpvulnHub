#  漏洞预警 | SeaCMS海洋影视管理系统远程代码执行漏洞   
浅安  浅安安全   2024-12-28 00:00  
  
**0x00 漏洞编号**  
- # CVE-2024-55461  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
海洋CMS是为解决站长核心需求而设计的内容管理系统，一套程序自适应电脑、手机、平板、APP多个终端入口，无任何加密代码、安全有保障，是您最佳的建站工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SVAS3cgxzDKew2rV0NjbAZGHtibZEdHTrPpsFL4Mgko79pJicmq3XiarhxlzdCkrkibN4f6Fd8cibA5Y3g/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2024-55461**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
****  
  
**简述：**  
海洋CMS的/ebak/phome.php接口处存在远程代码执行漏洞，经过身份验证的远程攻击者可利用该漏洞执行任意代码写入后门文件，进而控制整个web服务器。  
  
**0x04 影响版本**  
- 海洋CMS <= 13.0  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.seacms.net/  
  
  
  
