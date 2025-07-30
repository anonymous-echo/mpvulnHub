#  GitHub 上的虚假 LDAPNightmware 漏洞传播信息窃取恶意软件   
Rhinoer  犀牛安全   2025-02-11 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBntTPia56CVs3NYUzH6WltHG8ta04EwPWWgAXluwrJ0QNm3qiayc6keh4qxk1h1RJBUibB2wY5vRLa4A/640?wx_fmt=png&from=appmsg "")  
  
GitHub 上针对 CVE-2024-49113（又名“LDAPNightmare”）的欺骗性概念验证 (PoC) 漏洞利用信息窃取恶意软件感染用户，该恶意软件会将敏感数据泄露到外部 FTP 服务器。  
  
这种策略并不新颖，因为在 GitHub 上已经有多起以 PoC 漏洞为伪装的恶意工具案例。  
  
然而，趋势科技发现的这起案例凸显出，攻击者继续使用这种策略来诱骗毫无戒心的用户感染恶意软件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBntTPia56CVs3NYUzH6WltHGiabBaibOIyNiaGXhmPSXhD60YPJHU4WAACLTR8Dw3n1aXU3vWxVgdiagiaQ/640?wx_fmt=png&from=appmsg "")  
  
欺骗性的利用  
  
Trend Micro 报告称，恶意 GitHub 存储库包含一个项目，该项目似乎是从 SafeBreach Labs于 2025 年 1 月 1 日发布的 CVE-2024-49113合法 PoC分叉而来。  
  
该漏洞是影响 Windows 轻量级目录访问协议 (LDAP) 的两个漏洞之一，微软已在2024 年 12 月的补丁星期二修复了该漏洞，另一个漏洞是严重的远程代码执行 (RCE) 问题，其编号为 CVE-2024-49112。  
  
SafeBreach 最初关于 PoC的博客文章错误地提到了 CVE-2024-49112，而他们的 PoC 针对的是 CVE-2024-49113，这是一个严重程度较低的拒绝服务漏洞。  
  
这个错误即使后来得到了纠正，也引起了人们对 LDAPNightmare 及其攻击潜力的更大兴趣和关注，这可能正是威胁行为者试图利用的。  
  
从恶意存储库下载 PoC 的用户将获得一个 UPX 打包的可执行文件“poc.exe”，该文件在执行后会将 PowerShell 脚本放入受害者的 %Temp% 文件夹中。  
  
该脚本在受感染的系统上创建一个计划作业，该作业执行一个编码脚本，该脚本从 Pastebin 获取第三个脚本。  
  
此最终有效载荷收集计算机信息、进程列表、目录列表、IP 地址和网络适配器信息以及已安装的更新，并使用硬编码凭据将它们以 ZIP 存档形式上传到外部 FTP 服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBntTPia56CVs3NYUzH6WltHGz7YejOjfDiciay72OvfXObyDOQMiagFiaxkDsHsvOhG4zNCAFTWYryCWHA/640?wx_fmt=png&from=appmsg "")  
  
GitHub 用户在寻找公开漏洞用于研究或测试时需要谨慎，最好只信任信誉良好的网络安全公司和研究人员。  
  
攻击者过去曾  
试图冒充知名的安全研究人员，因此验证存储库的真实性也至关重要。  
  
如果可能的话，请在系统上执行代码之前检查代码，将二进制文件上传到 VirusTotal，并跳过任何看起来模糊的内容。  
  
  
信息来源：BleepingComputer  
  
