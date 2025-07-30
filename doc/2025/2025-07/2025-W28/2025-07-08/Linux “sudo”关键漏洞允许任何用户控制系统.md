> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NTUzNzY3Ng==&mid=2247489168&idx=1&sn=931ea8f0161289c6d7003a69fb820de6

#  Linux “sudo”关键漏洞允许任何用户控制系统  
 SecHub网络安全社区   2025-07-08 03:29  
  
****  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
## 🌟简介  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrmFP1KibshFcUFuWkyKQnCP8VpOWCvmxF1DreUH9msP53Pv9bC7s5Cib9icpvRbC7xwSViaEnBibbhyRQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**全球数百万台 Linux 系统，包括运行关键服务的系统，都可能受到一种新的、易于利用的 sudo 漏洞的威胁，该漏洞允许未经授权的用户在 Ubuntu、Fedora 和其他服务器上以 root 身份运行命令。**  
  
Sudo 是一个允许用户在 Linux 机器上以 root 或超级用户身份运行命令的工具。Stratascale 网络安全研究小组（CRU）发现了影响 sudo 的两个关键漏洞。  
  
安全研究人员警告称，任何用户都可能迅速获得无限制的访问权限。攻击者可以利用这一点，以 root 身份运行任意命令，并完全控制系统。  
  
该漏洞首次出现在 2023 年 6 月发布的 1.9.14 版本中，并在 2025 年 6 月 30 日发布的最新 sudo 版本 1.9.17p1 中修复。该漏洞已在 Ubuntu 和 Fedora 服务器上得到验证，但可能涉及更多系统。  
  
这些漏洞可能导致在受影响系统上提升权限至 root.  
  
他们敦促管理员尽快安装最新的 sudo 软件包，因为不存在其他解决方案。  
  
Stratascale 网络安全研究单位的 Rich Mirch 解释说：“默认的 sudo 配置存在漏洞。”  
  
研究人员公开发布了概念验证代码，其他团队能够复制这一发现。  
## 漏洞涉及 sudo chroot 功能  
  
关键漏洞存在于 sudo 中很少使用的 chroot 选项中。此选项修改特定进程的工作根目录，并限制对文件系统的其他部分的访问。  
  
虽然其目的是将用户锁定在其主目录中，但漏洞允许他们突破限制并提升权限。利用这些漏洞不需要为用户定义任何 sudo 规则。  
  
“因此，如果安装了易受攻击的版本，任何本地无特权的用户都可能提升权限到 root，”研究人员表示。  
  
利用这个漏洞，攻击者需要在用户指定的根目录下创建一个 /etc/nsswitch.conf 文件，并诱使 sudo 加载任意共享库。该文件定义了系统如何解析用户账户、组、主机名、服务等内容。  
  
sudo 维护者确认了该问题，并在版本 1.9.17p1 中弃用了 chroot 选项。  
  
“攻击者可以利用 sudo 的 -R (--chroot) 选项以 root 身份运行任意命令，即使这些命令没有在 sudoers 文件中列出，”他们在一份 公告 中表示。  
  
Mirch 的脚本展示了非特权攻击者如何创建一个临时目录，添加一个函数以授予自身完全 root 访问权限的文件，编译一个恶意共享库来加载它，然后利用 chroot 选项诱使 sudo 以提升的权限执行它。因此，攻击者可以有效地完全控制系统。  
  
由于降低环境安全性的风险，建议管理员避免使用 chroot 选项。  
  
“搜索环境中任何对 chroot 选项的使用。检查/etc/sudoers 中定义的所有 Sudo 规则，以及/etc/sudoers.d 下的文件。如果 Sudo 规则存储在 LDAP 中，请使用 ldapsearch 等工具导出规则，”Mirch 写道。  
  
这一漏洞可能影响数百万台系统。德国出版物 heise.de 甚至发现了一家大型德国云托管提供商上全新安装的 Ubuntu 虚拟机仍然容易受到该漏洞的影响，尽管已经发布了补丁。  
  
**影响版本**  

```
CVE-2025-32462：
1.9.0 <= sudo <= 1.9.17
1.8.8 <= sudo <= 1.8.32
CVE-2025-32463：
1.9.14 <= sudo <= 1.9.17
注意：Sudo 的旧版本（当前 <= 1.8.32）不易受到攻击，因为不存在 chroot 功能。
```

  
相关POC：  

```
https://github.com/K1tt3h/CVE-2025-32463-POC
```

  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**  
sechub安全  
  
**哔哩号：**  
SecHub官方账号  
  
  
  
