#  修复了Fortinet FortiOS中的多个漏洞   
鹏鹏同学  黑猫安全   2024-06-14 09:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9VK68asAD9kFOf4ffmUibSusnkrE6UfKASyiagiaKTS7xPMQGlfMRibiapIaDvlCW0M0QQQ1kLUia2qu7A/640?wx_fmt=png&from=appmsg "")  
  
Fortinet解决了FortiOS和其他产品中的多个漏洞，包括一些代码执行漏洞。公司表示，FortiOS命令行解释器中存在的多个基于栈的缓冲区溢出漏洞（CWE-121），统称为CVE-2024-23110（CVSS评分为7.4），可以被经过身份验证的攻击者利用，通过特制的命令行参数实现代码或命令执行。  
  
公司发布的公告中指出：“FortiOS命令行解释器中存在的多个基于栈的缓冲区溢出漏洞（CWE-121）可能允许经过身份验证的攻击者通过特制的命令行参数执行未经授权的代码或命令。” 这些漏洞是由Fortinet产品安全团队的Gwendal Guégniaud发现的。  
  
这些漏洞影响以下版本的Fortinet FortiOS：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8dBEfDPEce9VK68asAD9kFOf4ffmUibSuLl88QB0MUuFlJufick3sZJw27lcmLOZoiaVAiazpab7Z7FNpNRZLMlVpg/640?wx_fmt=png&from=appmsg "")  
  
公司还解决了以下中等严重性问题：  
- CVE-2024-26010：FortiOS、FortiProxy、FortiPAM和FortiSwitchManager中的一个基于栈的溢出漏洞 [CWE-124]，可能允许远程攻击者通过向fgfmd守护进程发送特制的数据包来执行任意代码或命令。然而，该漏洞的可利用性取决于攻击者无法控制的具体条件。  
  
- CVE-2024-23111：FortiOS和FortiProxy重启页面中的一个跨站脚本漏洞 [CWE-79]，可能使具有超级管理员访问权限的远程攻击者通过特制的HTTP GET请求执行JavaScript代码。  
  
- CVE-2023-46720：FortiOS中的多个基于栈的缓冲区溢出漏洞 [CWE-121]，可能允许经过身份验证的攻击者通过使用特制的CLI命令执行任意代码。  
  
公司还修复了一个低严重性问题，编号为CVE-2024-21754。  
  
公司未透露上述问题中是否有任何一个在野外被积极利用。  
  
  
