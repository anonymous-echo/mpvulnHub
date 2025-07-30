> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493630&idx=1&sn=45861fae4709fa33d3f7e3009fc75254

#  漏洞预警 | Wing FTP服务器远程代码执行漏洞  
浅安  浅安安全   2025-07-07 00:01  
  
**0x00 漏洞编号**  
- # CVE-2025-47812  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Wing FTP服务器是一款跨平台的文件传输服务软件，支持FTP、SFTP、FTPS等多种协议，具备图形化管理界面和灵活的权限控制，适用于企业文件共享与服务器数据传输场景。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SUiaib8Dmib97zg6lgzjicwe4iayQicq6O3EejU7icMxXEAum3sQ0iaFPjOaUKRwfnF7fgicxLKhoj3ozzsPow/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2025-47812**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意命令  
  
**简述：**  
Wing FTP服务器的/loginok.html接口存在远程代码执行漏洞，攻击者可利用用户名参数中的NULL字节注入Lua代码，实现任意命令执行。  
  
**0x04 影响版本**  
- Wing FTP服务器 <= 7.4.3  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
**目前官方已发布漏洞修复版本，建议用户升级到安全版本****：**  
  
https://www.wftpserver.com/zh/  
  
  
  
