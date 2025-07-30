#  GNU Screen 多漏洞曝光，本地提权与终端劫持风险浮现   
 FreeBuf   2025-05-13 10:16  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![GNU Screen漏洞setuid-root提权示意图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOLMac5XMiaCZbZsyz6bOticKibvEhHde4bGGJXte1NlrtJ05K8JvvBgX3PSbL3WibFuu4331nk2nJjg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
SUSE安全团队全面审计发现，广泛使用的终端复用工具GNU Screen存在一系列严重漏洞，包括可导致本地提权至root权限的缺陷。这些问题同时影响最新的Screen 5.0.0版本和更普遍部署的Screen 4.9.x版本，具体影响范围取决于发行版配置。  
  
  
尽管GNU Screen是类UNIX系统中管理终端会话的核心工具，但研究显示其存在重大风险——特别是当Screen以setuid-root权限安装以支持多用户功能时。  
  
### Part01  
### 关键漏洞分析  
  
  
**1. CVE-2025-23395：logfile_reopen()函数本地提权漏洞**  
  
  
最严重的漏洞允许本地权限提升。在Screen 5.0.0中，logfile_reopen()函数在重新打开用户定义的日志文件时未能正确丢弃提升的权限，使得攻击者可以向root所有的文件写入任意数据。  
  
  
报告警告称："非特权用户可以在任意位置创建root所有的文件...所有写入Screen PTY的数据都将被记录到该文件中"。该漏洞可通过操纵日志文件的链接计数强制重新打开来触发，已在采用setuid-root方式安装Screen的Arch Linux和NetBSD系统上得到确认。  
  
  
**2. CVE-2025-46802：终端重连竞争条件漏洞**  
  
  
另一个重大缺陷涉及多用户会话重新连接时Attach()函数中的竞争条件。当被调用时，Screen会临时将终端设备模式设置为0666，使系统上任何进程都能读写用户的TTY。  
  
  
SUSE表示："我们使用简单的Python脚本每两到三次尝试就能成功打开受影响的TTY"。虽然这种基于chmod的方法原本旨在实现会话守护进程间的通信，但却为击键拦截或命令注入创造了危险窗口。  
  
  
**3. CVE-2025-46803：默认全局可写PTY漏洞**  
  
  
Screen 5.0.0还将默认PTY模式改为0622，使其全局可写。这使得任何用户都能向Screen管理的PTY写入数据，重现了TTY劫持漏洞的部分特征——现在这已成为默认行为。除非明确覆盖编译时配置，否则Arch Linux和NetBSD等发行版都会受到影响。  
  
### Part02  
### 其他安全缺陷  
  
  
**1. CVE-2025-46804：文件存在性信息泄露**  
  
  
通过滥用SCREENDIR环境变量，可诱骗Screen泄露root所有文件的存在及类型，揭示路径是目录、文件还是不可访问。  
  
  
**2. CVE-2025-46805：信号处理竞争条件**  
  
  
在对CVE-2023-24626的不完整修复中，Screen的信号发送逻辑仍存在竞争条件。攻击者可利用权限检查与实际信号发送之间的TOCTOU（检查时间/使用时间）窗口，向非目标进程发送SIGHUP或SIGCONT等信号。  
  
  
**3. strncpy()误用导致的缓冲区溢出**  
  
  
虽然未分配CVE编号，但Screen 5.0.0中存在一个不可利用的缓冲区溢出问题。当用户尝试向活动Screen会话发送含多个参数的命令时，可能导致崩溃。该问题源于用strncpy()不当替换strcpy()的行为，在启用FORTIFY_SOURCE保护的Arch Linux系统上已观察到崩溃现象。  
  
  
**4. 受影响发行版**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibOLMac5XMiaCZbZsyz6bOticUDMvmtF47tdCTasfIRqNkwhWsQLkXmHOich2j3UZEsxjZBic3xXOhmnw/640?wx_fmt=png&from=appmsg "")  
  
###   
### Part03  
### 安全建议  
  
  
SUSE强烈建议现阶段不要以setuid-root权限安装Screen。报告指出，许多问题源于过时的权限管理模型和5.0.0版本代码重构期间引入的退步。  
  
  
SUSE建议："Screen存在更广泛的设计问题：它始终以提升的权限运行，仅针对被认为危险的操作选择性丢弃权限。对于健壮的setuid-root程序，应该采用相反的方式：默认丢弃权限，仅在确实需要提升权限的操作时临时获取。"他们建议将多用户支持设为可选功能，可能限制为受信任组使用，并提出更广泛的架构变更以确保安全的权限处理。  
  
  
**参考来源：**  
  
**Multiple CVEs in GNU Screen: Local Root Exploit and TTY Hijacking Discovered**https://securityonline.info/multiple-cves-in-gnu-screen-local-root-exploit-and-tty-hijacking-discovered/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320016&idx=1&sn=8488591c0f5d5cf6414cef9bfa60bf62&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
