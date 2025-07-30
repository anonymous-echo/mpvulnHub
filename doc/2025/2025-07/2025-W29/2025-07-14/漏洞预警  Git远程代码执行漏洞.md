> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493700&idx=2&sn=7a27ce9d8f9c38ab8ded8423985240d6

#  漏洞预警 | Git远程代码执行漏洞  
浅安  浅安安全   2025-07-14 00:00  
  
**0x00 漏洞编号**  
- CVE-2025-48384  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Git是一个分布式版本控制系统，用于跟踪文件变化并协作开发软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXibicaYVFNppHJFsXuaib4e9IIZbelz6lqfxHy5wJKaF4LJxIibZ8B7yiaPbbbAT28gxsfVoku7VicqcsA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-48384**  
  
**漏洞类型：**  
远程代码执行  
  
**影响：**  
执行任意代码  
  
**简述：**  
Git存在远程代码执行漏洞，由于其配置文件对回车符的处理不当，在类Unix平台下，当使用git clone --recursive命令时，Git会从.gitmodules文件读取子模块路径并检出相应的子模块。然而，若子模块路径包含尾部回车符（^M），Git会错误地处理该路径，导致回车符丢失并将路径写入.git/modules/foo/config中，进而使子模块被检出到错误路径。若存在符号链接指向错误路径，并且子模块包含可执行的post-checkout钩子脚本，该脚本可能在检出时意外执行，从而导致远程代码执行。  
  
**0x04 影响版本**  
- Git <= 2.50.0  
  
**0x05 POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://github.com/git/git  
  
  
  
