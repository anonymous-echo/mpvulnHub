#  新的 Linux 漏洞允许通过 Ubuntu、RHEL、Fedora 中的核心内存转储窃取密码哈希值   
会杀毒的单反狗  军哥网络安全读报   2025-06-02 02:15  
  
**导****读**  
  
  
  
据 Qualys 威胁研究部门 (TRU) 称，Ubuntu、Red Hat Enterprise Linux 和 Fedora 中的核心转储处理程序apport和systemd-coredump中发现了两个信息泄露漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaFCibweXWWdFic8bVv1gBNnmrr4MT9l0huyLktQxGe4yu67jAfadxIwyQB71TUhgCBF4NsH1PjJq7Vw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这两个漏洞的编号分别为CVE-2025-5054 和 CVE-2025-4598，均为竞争条件漏洞，可能使本地攻击者获取敏感信息的访问权限。Apport 和 systemd-coredump 等工具旨在处理 Linux 系统中的崩溃报告和核心转储。  
  
  
Qualys TRU 产品经理 Saeed Abbasi表示：“这些竞争条件允许本地攻击者利用 SUID 程序并获得对生成的核心转储的读取权限。”  
  
  
这两个缺陷的简要描述如下：  
  
  
CVE-2025-5054（CVSS 评分：4.7）- Canonical apport 软件包（包括 2.32.0 版本）中存在竞争条件，允许本地攻击者利用命名空间通过 PID 重用泄露敏感信息  
  
  
CVE-2025-4598（CVSS 评分：4.7）- systemd-coredump 中的竞争条件允许攻击者强制 SUID 进程崩溃，并将其替换为非 SUID 二进制文件，以访问原始特权进程 coredump，从而使攻击者能够读取原始进程加载的敏感数据（例如 /etc/shadow 内容）  
  
  
SUID 是“设置用户 ID”的缩写，是一种特殊的 文件权限，允许用户以其所有者的权限而不是他们自己的权限来执行程序。  
  
  
Canonical 的 Octavio Galland表示：“在分析应用程序崩溃时，apport 会尝试检测崩溃进程是否在容器内运行，然后再对其进行一致性检查。”  
  
  
“这意味着，如果本地攻击者设法在特权进程中引发崩溃，并迅速将其替换为位于 mount 和 pid 命名空间内的另一个具有相同进程 ID 的进程，apport 将尝试将核心转储（可能包含属于原始特权进程的敏感信息）转发到命名空间中。”  
  
  
Red Hat 表示，由于利用该漏洞的复杂性，CVE-2025-4598 的严重性被评为中等，并指出攻击者必须首先赢得竞争条件并拥有非特权的本地帐户。  
  
  
Amazon Linux、Debian和Gentoo也发布了类似的安全公告。值得注意的是，Debian 系统默认不会受到 CVE-2025-4598 的影响，因为除非手动安装 systemd-coredump 软件包，否则它们不包含任何核心转储处理程序。CVE-2025-4598 不影响 Ubuntu 版本。  
  
  
Qualys 还针对这两个漏洞开发了概念验证 (PoC) 代码，演示了本地攻击者如何利用崩溃的 unix_chkpwd 进程的核心转储（该进程用于验证用户密码的有效性）从 /etc/shadow 文件中获取密码哈希值。  
  
  
详细漏洞公告：  
  
https://blog.qualys.com/vulnerabilities-threat-research/2025/05/29/qualys-tru-discovers-two-local-information-disclosure-vulnerabilities-in-apport-and-systemd-coredump-cve-2025-5054-and-cve-2025-4598  
  
  
新闻链接：  
  
https://thehackernews.com/2025/05/new-linux-flaws-allow-password-hash.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
