#  Jenkins RCE 漏洞目前已公布   
胡金鱼  嘶吼专业版   2024-02-18 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
Jenkins是一种开源自动化服务器，广泛用于软件开发，特别是持续集成 (CI) 和持续部署 (CD)。它在自动化软件开发过程的各个部分（例如构建、测试和部署应用程序）方面发挥着关键作用，支持着一千多个集成插件，可供各种规模的组织或大型企业使用。  
  
SonarSource研究人员在Jenkins中发现了两个缺陷，这些缺陷使攻击者能够访问服务器中的数据并在某些条件下执行任意CLI命令。  
  
第一个漏洞被评为严重漏洞，编号为CVE-2024-23897，允许有“总体/读取”权限，未经身份验证的攻击者可以从Jenkins服务器上的任意文件读取数据。没有此权限的攻击者仍然可以读取文件的前几行，其数量取决于可用的CLI命令。  
  
该缺陷源于Jenkins中args4j命令解析器的默认行为，当参数以“@”字符开头时，该解析器会自动将文件内容扩展为命令参数，从而允许读取Jenkins控制器文件系统上的任意文件。  
  
利用该特定缺陷可能会导致管理员权限升级和任意远程代码执行。然而，此步骤取决于必须满足的某些条件，这些条件对于每种攻击变体都是不同的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2icbzJEfxxBnibVEiboAPwm2QZ2CN8aIticDBJxLjNsPCTetelRiaJSV2J8cG6HaOoQzgKTEQapxyW4vOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
开发图   
  
第二个缺陷被追踪为CVE-2024-23898，是一个跨站点WebSocket劫持问题，攻击者可以通过诱骗用户单击恶意链接来执行任意CLI命令。  
  
网络浏览器中现有的保护策略应该可以减轻此错误带来的风险，但由于这些策略缺乏普遍执行，这种风险仍然存在。  
  
SonarSource于2023年11月13日向Jenkins安全团队报告了这些缺陷，并在接下来的几个月内帮助验证了修复程序。  
  
2024年1月24日，Jenkins发布了版本2.442和LTS 2.426.3这两个缺陷的修复程序以及公告 ，分享了各种攻击场景和利用途径，以及修复说明和解决方法的更新。  
# 可用的漏洞  
  
许多研究人员根  
据现有Jenkins缺陷的大量信息，重现了一些攻击场景，并创建了在GitHub上发布的有效PoC漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2icbzJEfxxBnibVEiboAPwm2QZMrW7ialzrsVnwOjwDGNvmFGY3UHKndJ01WEdzwp3ISQWYTZXtKbWcPg/640?wx_fmt=jpeg&from=appmsg "")  
  
PoC针对CVE-2024-23897，攻击者可以在未修补的Jenkins服务器上远程执行代码。其中许多PoC已经过验证，因此扫描暴露服务器的攻击者可以获取脚本并在进行最少修改或无需修改的情况下尝试。  
  
此外，一些研究报告说，他们的Jenkins蜜罐已经捕获了野外活动，这表明黑客已经开始利用这些漏洞来进行攻击。  
  
参考及来源：https://www.bleepingcomputer.com/news/security/exploits-released-for-critical-jenkins-rce-flaw-patch-now/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icbzJEfxxBnibVEiboAPwm2QZKCrMAnPhpDibEPmmzMa6x391QaaRuyTE1EkmuzPjVEh9ibWJhmFxx6Ew/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icbzJEfxxBnibVEiboAPwm2QZPkiatZSWMibtGqM2bHia0s0ngNCvvvyISTvfy22WQjkhwNhtMj3ZoKK2g/640?wx_fmt=png&from=appmsg "")  
  
  
