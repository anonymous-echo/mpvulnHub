> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NzkxOTQ0OA==&mid=2247484602&idx=1&sn=ab57d795ad72fed932c8e1a102cc3a58

#  严重 Sudo 漏洞使本地用户获得 Linux 上的 Root 访问权限，影响主要发行版  
原创 黑客节点  菜鸟学渗透   2025-07-07 23:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZklfAg4WQQfPdLHq2VDjeCThAqvLzValLZDiazngIV8kHPesZCHNcp8pz1P7KLic1JvEv3OMdZDGYXw/640?wx_fmt=png&from=appmsg "")  
  
网络安全研究人员披露了 Linux 和类 Unix 操作系统的 Sudo 命令行实用程序中的两个安全漏洞，这些漏洞可能使本地攻击者能够将其权限提升到易受攻击的机器上的 root 权限。  
  
该漏洞的简要描述如下：  
- **CVE-2025-32462**（CVSS 评分：2.8）- 1.9.17p1 之前的 Sudo，当与指定既不是当前主机也不是 ALL 的主机的 sudoers 文件一起使用时，允许列出的用户在非预期的机器上执行命令  
- **CVE-2025-32463**（CVSS 评分：9.3）- 1.9.17p1 之前的 Sudo 允许本地用户获得 root 访问权限，因为用户控制目录中的“ /etc/nsswitch.conf ”与 --chroot 选项一起使用  
Sudo 是一个命令行工具，允许低权限用户以其他用户（例如超级用户）的身份运行命令。通过使用 sudo 执行指令，其理念是强制执行最小权限原则，允许用户无需提升权限即可执行管理操作。  
  
该命令通过名为“/etc/sudoers”的文件进行配置，该文件决定“谁可以在哪些机器上以哪些用户身份运行哪些命令，还可以控制特殊事项，例如是否需要为特定命令输入密码”。  
  
Stratascale 的研究员 Rich Mirch 发现并报告了这些漏洞，他表示CVE-2025-32462 漏洞已经潜伏了超过 12 年。该漏洞源于 Sudo 的“-h”（主机）选项，该选项可以列出用户在不同主机上的 sudo 权限。该功能于 2013 年 9 月启用。  
  
然而，当运行带有引用不相关远程主机的主机选项的 Sudo 命令时，所发现的错误使得可以执行远程主机允许在本地计算机上运行的任何命令。  
  
Sudo 项目维护者 Todd C. Miller 在一份安全公告中表示： “这主要影响那些使用分发到多台机器的通用 sudoers 文件的网站。使用基于 LDAP 的 sudoers（包括 SSSD）的网站也受到类似影响。”  
  
另一方面，CVE-2025-32463 利用 Sudo 的“-R”（chroot）选项，以 root 身份运行任意命令，即使这些命令未在 sudoers 文件中列出。这同样是一个严重程度为“严重”的漏洞。  
  
Mirch表示： “默认的 Sudo 配置存在漏洞。虽然该漏洞涉及 Sudo chroot 功能，但它不需要为用户定义任何 Sudo 规则。因此，如果安装了存在漏洞的版本，任何本地非特权用户都有可能将权限提升到 root 权限。”  
  
换句话说，该漏洞允许攻击者通过在用户指定的根目录下创建“/etc/nsswitch.conf”配置文件来诱骗 sudo 加载任意共享库，并可能以提升的权限运行恶意命令。  
  
米勒表示， Sudo 的未来版本中将彻底删除 chroot 选项，并且支持用户指定的根目录“容易出错”。  
  
继 2025 年 4 月 1 日负责任地披露这些漏洞后，这些漏洞已在上个月底发布的 Sudo 1.9.17p1 版本中得到修复。由于许多 Linux 发行版都预装了 Sudo，因此也发布了安全公告：  
- **CVE-2025-32462** - AlmaLinux 8、AlmaLinux 9、Alpine Linux、Amazon Linux、Debian、Gentoo、Oracle Linux、Red Hat、SUSE和Ubuntu  
- **CVE-2025-32463** - Alpine Linux、Amazon Linux、Debian、Gentoo、Red Hat、SUSE和Ubuntu  
建议用户应用必要的修复并确保 Linux 桌面发行版已使用最新的软件包进行更新。  
  
