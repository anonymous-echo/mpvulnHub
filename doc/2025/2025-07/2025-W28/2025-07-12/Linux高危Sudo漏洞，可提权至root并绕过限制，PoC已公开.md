> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIyMDEzMTA2MQ==&mid=2651168678&idx=1&sn=ca4103b2ea097dfda3fc23c85d5c9f5e

#  Linux高危Sudo漏洞，可提权至root并绕过限制，PoC已公开  
 黑客技术与网络安全   2025-07-12 03:01  
  
> 来自：FreeBuf，作者：大仙  
> 链接：https://www.freebuf.com/articles/system/437269.html  
  
  
在Linux权限管理领域，Sudo堪称守护神。作为root访问的看门人，它掌控着系统最高权限的钥匙。但当这个守卫者被一个巧妙技巧欺骗时会发生什么？  
  
  
Stratascale网络研究部门（CRU）发布的最新安全公告显示，Sudo中存在CVE-2025-32463和CVE-2025-32462  
两个高危漏洞  
。这些潜伏在全球最受信任的命令提权工具中的缺陷，能让攻击者绕过配置保护措施，即使被明确拒绝访问也能将权限提升至root。  
  
  
**Part01**  
## CVE-2025-32463：chroot隔离失效  
###   
  
**受影响版本**  
：Sudo 1.9.14至1.9.17全系列  
  
  
有时，我们为了  
保护自己而  
筑起的围墙，反而会成为攻击者的入口。CVE-2025-32463（  
CVSS评分9.3  
）正是这样一个本地提权漏洞，它滥用了Sudo鲜为人知的
```
--chroot
```

  
（-R）选项。  
  
  
stratascale在公告中表示："攻击者可利用sudo的-R（--chroot）选项以root身份执行任意命令，即使这些命令未列在sudoers文件中"。  
  
  
问题的根源在于Sudo从1.9.14版开始实现chroot()的方式。该工具开始在评估sudoers文件之前解析chroot环境中的路径。这意味着攻击者可以诱骗Sudo读取伪造的/etc/nsswitch.conf文件——该文件会指示加载恶意共享库如libnss_/woot1337.so.2。诱骗的结果就是，无需sudoers权限即可  
以 root 身份执行任意代码  
。  
  
  
CRU提供的概念验证脚本（sudo-chwoot.sh）直观展示了攻击效果：  

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


```


```


```
只需一瞬间，低权限（lowpriv）用户就获得了最高权限。
```


```


```

  
Sudo 1.9.17p1通过回退1.9.14版的修改并彻底弃用--chroot功能修复此问题。补丁移除了pivot_root()逻辑，使得在命令匹配期间无法调用chroot()。  
  
  
**Part02**  
### CVE-2025-32462：不可信的主机参数  
  
  
**受影响版本**  
：Sudo 1.8.8至1.9.17全系列  
  
  
虽然不如上一个chroot漏洞重要，但CVE-2025-32462（  
CVSS评分2.8  
）同样危险——尤其在采用集中式sudoers文件管理多主机的企业环境中。  
  
  
CRU表示："该漏洞使sudoers规则中的主机名部分失效，因为用户可以在评估规则时自行设置要使用的主机"。设计用于让用户查看其他主机权限的
```
--host
```

  
（-h）选项本不应支持命令执行，但由于一个存在12年的逻辑缺陷，它可以绕过限制。  
  
  
以公告中的真实案例为例：  

```
alice cerebus = ALL
```


```
此规则本应仅允许Alice在cerebus主机上执行命令。但利用该漏洞，Alice只需在sudo命令中添加
-h cerebus
```


```


```

  
Sudo 1.9.17p1将
```
--host
```

  
选项严格限制为最初设计的功能：列出规则。现在若尝试将其用于其他操作，将触发用法错误提示。  
  
  
**Part03**  
### 漏洞共性特征及解决办法  
  
  
这两个漏洞都无需修改sudoers文件或获取管理员批准即可实现权限提升。公告总结指出："由于这种行为，任何本地用户都可以诱骗Sudo加载任意共享对象，从而导致以root身份执行任意代码"。  
  
  
目前，这两个漏洞均已被修复，建议用户升级到最新版  
Sudo 1.9.17p1。  
  
  
**参考来源：**  
  
Critical Sudo Flaw (CVE-2025-32463, CVSS 9.3): Root Privilege Escalation & Host Bypass, PoC Available  
  
https://securityonline.info/critical-sudo-flaws-cve-2025-32463-cvss-9-3-root-privilege-escalation-host-bypass-poc-available/  
  
  
**---END---**  
  
