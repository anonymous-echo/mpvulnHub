#  Ubuntu Linux 受到“需要重启”漏洞的影响，该漏洞会导致本地提权到 root   
Rhinoer  犀牛安全   2024-11-29 16:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrXtIpdfnxCpxDIib7YLWHm7icV0TCvMCyQ9ths8c1RzCiaCHSFR5G3iaMSQ/640?wx_fmt=png&from=appmsg "")  
  
自 10 多年前推出的 Ubuntu Linux 21.04 版本以来，在默认使用的 needrestart 实用程序中发现了五个本地权限提升 (LPE) 漏洞。  
  
这些漏洞由 Qualys 发现，编号为 CVE-2024-48990、CVE-2024-48991、CVE-2024-48992、CVE-2024-10224 和 CVE-2024-11003。它们是在 2014 年 4 月发布的 needrestart 0.8 版本中引入的，并于昨天在 3.8 版本中修复。  
  
Needrestart是 Linux 上常用的实用程序，包括 Ubuntu Server，用于识别包更新后需要重新启动的服务，确保这些服务运行最新版本的共享库。  
  
LPE 漏洞总结  
  
Qualys 发现的五个漏洞允许对易受攻击的 Linux 系统具有本地访问权限的攻击者无需用户交互即可将其权限提升到 root 权限。  
  
关于这些漏洞的完整信息已在单独的文本文件中提供，但摘要如下：  
- CVE-2024-48990：Needrestart 使用从正在运行的进程中提取的 PYTHONPATH 环境变量执行 Python 解释器。如果本地攻击者控制此变量，他们可以通过植入恶意共享库在 Python 初始化期间以 root 身份执行任意代码。  
  
- CVE-2024-48992：needrestart 使用的 Ruby 解释器在处理攻击者控制的 RUBYLIB 环境变量时存在漏洞。这允许本地攻击者通过向进程注入恶意库以 root 身份执行任意 Ruby 代码。  
  
- CVE-2024-48991：needrestart 中的竞争条件允许本地攻击者用恶意可执行文件替换正在验证的 Python 解释器二进制文件。通过仔细计算替换时间，他们可以诱骗 needrestart 以 root 身份运行其代码。  
  
- CVE-2024-10224：Perl 的 ScanDeps 模块（由 needrestart 使用）对攻击者提供的文件名处理不当。攻击者可以制作类似于 shell 命令的文件名（例如 command|），以便在打开文件时以 root 身份执行任意命令。  
  
- CVE-2024-11003：Needrestart 对 Perl 的 ScanDeps 模块的依赖使其面临 ScanDeps 本身的漏洞，在处理攻击者控制的输入时，不安全地使用 eval() 函数可能导致任意代码执行。  
  
值得注意的是，为了利用这些漏洞，攻击者必须通过恶意软件或受感染的帐户本地访问操作系统，这在一定程度上降低了风险。  
  
然而，攻击者过去利用类似的 Linux 特权提升漏洞来获取 root 权限，包括Loony Tunables和利用 nf_tables 漏洞的漏洞，因此这个新的漏洞不应该仅仅因为它需要本地访问而被忽视。  
  
由于 needrestart 的广泛使用及其长期存在漏洞，上述漏洞可能为关键系统的特权提升创造机会。  
  
除了升级到 3.8 或更高版本（其中包含所有已识别漏洞的补丁）之外，还建议修改 needrestart.conf 文件以禁用解释器扫描功能，从而防止漏洞被利用。  
  
# Disable interpreter scanners. $nrconf{interpscan} = 0;  
  
这应该可以阻止 needrestart 执行具有潜在攻击者控制的环境变量解释器。  
  
  
信息来源：  
BleepingComputer  
  
