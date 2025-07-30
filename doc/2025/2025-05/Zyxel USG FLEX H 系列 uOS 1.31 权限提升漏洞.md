#  Zyxel USG FLEX H 系列 uOS 1.31 权限提升漏洞   
原创 Ots安全  Ots安全   2025-05-19 11:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tadG6T2xqePMAHHxyYQ9w9pvKbweMjxnVj8wwibyM8vslRmKUuzQiay0aTK2Bg0rV7fkV2ia9lrwWfUIQ/640?wx_fmt=jpeg&from=appmsg "")  
  
今天早上，当我刷到 Exploit Database 的一条推文时，心头不由得一震——Zyxel USG FLEX H 系列防火墙 uOS 1.31 版本竟然爆出了一个本地权限提升漏洞（CVE-2025-1731）！作为一个长期关注网络安全的技术爱好者，我立刻深入研究了这个漏洞的细节。不得不说，这个漏洞的技术细节和潜在影响让我既震惊又感慨。在这篇博客中，我将带大家一起剖析这个漏洞的来龙去脉，探讨它的技术原理、利用方式，以及对我们网络安全实践的启示。  
  
漏洞背景：Zyxel 的“安全承诺”与现实的碰撞  
  
Zyxel 是一家在网络设备领域有着深厚积累的厂商，其 USG FLEX H 系列防火墙主打企业级安全防护，搭载了全新的 Linux 内核操作系统 uOS。Zyxel 宣称 uOS 是“默认安全”（secure by default）的设计，这让我想起了多年前 Oracle 曾吹嘘的“牢不可破”（unbreakable）营销口号。然而，理想很丰满，现实很骨感。就在 2025 年 4 月 23 日，安全研究员 Marco Ivaldi 发现并披露了 CVE-2025-1731 漏洞，揭示了 uOS 在权限管理上的严重疏漏。  
  
这个漏洞影响了 Zyxel USG FLEX 100H（固件版本 1.31 ABXF.0）和 FLEX 200H（固件版本 1.31 ABWV.0）等设备，CVSS 评分高达 7.8（  
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H），属于高危漏洞。它的核心问题在于一个名为   
fermion-wrapper  
 的 setuid root 二进制程序存在设计缺陷，允许低权限用户通过符号链接攻击实现从普通用户（例如   
postgres  
 用户）到 root 的权限提升。  
  
技术细节：漏洞的成因与利用  
  
漏洞根源：符号链接与权限管理失误  
  
让我们剖析这个漏洞的成因。  
fermion-wrapper  
 是一个以 root 权限运行的 setuid 二进制文件，位于   
/usr/sbin/fermion-wrapper  
。当它被调用并传入   
register-status  
 参数时，会在   
/tmp  
 目录下创建一个文件。然而，这个过程存在两个致命的设计缺陷：  
1. 符号链接跟随问题（CWE-61）  
：  
fermion-wrapper  
 在处理   
/tmp  
 目录下的文件时，会盲目跟随符号链接（symbolic link）。这意味着攻击者可以通过创建一个符号链接，将目标文件指向文件系统中的任意位置，从而控制文件的创建位置。  
  
1. /tmp  
 目录缺少 sticky bit  
：在 Linux 系统中，  
/tmp  
 目录通常应该设置 sticky bit（通过   
chmod +t /tmp  
 实现），以确保只有文件的所有者才能删除或修改文件。然而，在 Zyxel uOS 1.31 中，  
/tmp  
 目录竟然没有设置 sticky bit，这使得攻击者可以轻松替换或操作其他用户创建的文件，进一步降低了攻击的难度。  
  
利用过程：从低权限到 root   
  
Marco Ivaldi 在 Exploit Database 提供的 PoC（概念验证代码）中详细展示了如何利用这个漏洞。让我带大家一步步拆解这个过程：  
1. 准备阶段  
：攻击者首先需要一个低权限的 shell 访问权限，例如   
postgres  
 用户。Zyxel 设备的某些功能（例如 PostgreSQL 相关服务）可能会允许低权限用户访问 Linux shell，这为攻击提供了入口。  
  
1. 创建符号链接  
：攻击者通过以下命令创建一个符号链接，将   
/tmp/register_status  
 指向   
/etc/cron.d/runme  
：  
  
```
ln -s /etc/cron.d/runme /tmp/register_status
```  
  
- 这里的   
/etc/cron.d/runme  
 是一个 cron 任务配置文件，攻击者希望通过   
fermion-wrapper  
 的行为在该位置创建一个可控文件。  
  
- 触发漏洞  
：攻击者运行   
fermion-wrapper register-status  
，此时程序会尝试在   
/tmp/register_status  
 写入数据。由于   
/tmp/register_status  
 是一个符号链接，实际写入的文件变成了   
/etc/cron.d/runme  
。  
  
- 写入恶意 cron 任务  
：攻击者在   
/etc/cron.d/runme  
 中写入以下内容：  
  
```
cp /bin/sh /tmp/pwned; chmod 4755 /tmp/pwned; rm /etc/cron.d/runme
```  
  
- 这段 cron 任务的作用是每分钟执行一次，将   
/bin/sh  
 复制到   
/tmp/pwned  
，并设置 setuid 权限（  
chmod 4755  
），最后删除 cron 文件以清理痕迹。  
  
- 等待与提权  
：大约一个小时后（取决于 cron 的执行周期），  
/tmp/pwned  
 文件将被创建，且具有 root 的 setuid 权限。攻击者只需运行   
/tmp/pwned -p  
 即可获得一个 root shell：  
  
```
$ /tmp/pwned -p# iduid=502(postgres) gid=502(postgres) euid=0(root) groups=502(postgres)
```  
  
  
整个过程简单而高效，攻击者仅需低权限 shell 访问和一点耐心，就能实现从普通用户到 root 的权限提升。  
  
Zyxel 的回应与补救措施  
  
Zyxel 在 2025 年 4 月 22 日发布了安全公告，承认了 CVE-2025-1731 和 CVE-2025-1732（另一个与恢复功能相关的权限管理漏洞）的存在，并为受影响的设备发布了补丁。官方建议用户尽快更新固件以修复漏洞。此外，Zyxel 表示正在重新评估   
/tmp  
 目录 sticky bit 的问题，但尚未将其列为正式漏洞。  
  
参考：  
  
https://security.humanativaspa.it/local-privilege-escalation-on-zyxel-usg-flex-h-series-cve-2025-1731/  
  
https://github.com/0xdea/exploits/blob/master/zyxel/raptor_fermion  
  
https://www.exploit-db.com/exploits/52293  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
