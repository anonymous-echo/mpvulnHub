#  【漏洞通告】glibc静态setuid程序dlopen代码执行漏洞安全风险通告   
 嘉诚安全   2025-05-21 00:39  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全  
监测到  
glibc静态setuid程序dlopen代码执行漏洞，漏洞编号为：  
CVE-2025-4802  
。  
  
  
setuid二进制文件是具有特殊权限的程序，可以以文件拥有者的身份执行。dlopen是一个动态加载库的函数，通常用于在运行时加载共享库。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
经研判，该漏洞为  
**高危**  
漏洞，  
漏洞源于静态setuid程序在调用dlopen时错误地使用LD_LIBRARY_PATH环境变量查找共享库，可能导致加载恶意库并执行攻击者控制的代码。  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
运行glibc版本为2.27至2.38的Linux系统（如Rocky Linux、Debian、Ubuntu等）可能受到影响，特别是使用静态setuid二进制文件的系统。  
  
**处置建议**  
  
  
  
  
  
  
  
  
1.升级版本  
  
官方已发布安全更新，建议受影响用户尽快升级到glibc 2.39或更高版本。  
  
在Debian/Ubuntu系统中：sudo apt update && sudo apt upgrade libc6  
  
在Rocky Linux/CentOS系统中：sudo dnf update glibc  
  
2.通用建议  
  
定期更新系统补丁，减少系统漏洞，提升服务器的安全性。  
  
加强系统和网络的访问控制，修改防火墙策略，关闭非必要的应用端口或服务，减少将危险服务（如SSH、RDP等）暴露到公网，减少攻击面。  
  
使用企业级安全产品，提升企业的网络安全性能。  
  
加强系统用户和权限管理，启用多因素认证机制和最小权限原则，用户和软件权限应保持在最低限度。  
  
启用强密码策略并设置为定期修改。  
  
3.参考链接  
  
https://www.openwall.com/lists/oss-security/2025/05/17/2  
  
https://sourceware.org/bugzilla/show_bug.cgi?id=32976  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1t8LLTibEW5NtxqlBL1HLib8jMO0PWtibWTWTFPOa3ND1lyaEQyBgp2fodg9A1XxvPjY7L6ILtK26MBGhofWE0ORw/640?wx_fmt=png&wx_ "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrJnzIYoQAv2nF3pgKm4SgdFkzuniaicBHQxgSdu0U0xyYbNDOcNkDMWCjwJNwKnic9ASAhhxEpkFL6lg/640?wx_fmt=gif&wx_ "")  
  
  
