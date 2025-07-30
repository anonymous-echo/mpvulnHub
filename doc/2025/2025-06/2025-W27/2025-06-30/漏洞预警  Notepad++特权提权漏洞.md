> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwMTQ0NDA1NQ==&mid=2247493534&idx=1&sn=1c90f3038da9a0abacd8adee20d5b5d9

#  漏洞预警 | Notepad++特权提权漏洞  
浅安  浅安安全   2025-06-29 16:01  
  
**0x00 漏洞编号**  
- CVE-2025-49144  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
Notepad++是一款免费的开源文本编辑器，支持多种编程语言的语法高亮和自动完成。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXge4Micx23dicocpZ55snE9DzMHRpHCGHFYKVPeV4na3jXDrpe3h2w79ia5C688fIDKUHmUl0EP8vTQ/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
  
**CVE-2025-49144**  
  
**漏洞类型：**  
特权提升  
  
**影响：**  
提升权限  
  
**简述：**  
Notepad++存在特权提升漏洞，攻击者可利用不受控制的可执行文件搜索路径在安装过程中，将恶意可执行文件加载为SYSTEM权限，从而实现本地特权提升。  
  
**0x04 影响版本**  
- U  
Notepad++ v8.8.1  
  
**0x05****POC状态**  
- 已公开  
  
**0x06****修复建议**  
  
******目前官方已发布漏洞修复版本，建议用户升级到安全版本****：******  
  
https://notepad-plus-plus.org/  
  
  
  
