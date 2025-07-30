#  【漏洞通告】Rsync多个漏洞安全风险通告   
 嘉诚安全   2025-01-20 03:57  
  
**漏洞背景**  
  
  
  
  
  
  
  
  
近日，嘉诚安全监测到Rsync发布安全公告，确认其服务端进程Rsyncd存在缓冲区溢出漏洞（CVE-2024-12084）、信息泄露漏洞（CVE-2024-12085）、文件泄露漏洞（CVE-2024-12086）、路径遍历漏洞（CVE-2024-12087）、路径遍历漏洞（CVE-2024-12088）和符号链接竞态条件漏洞（CVE-2024-12747）。  
  
  
rsync是一种常用的文件同步和传输工具，支持高效的增量备份。通过比较源和目标文件的差异，rsync只传输更改过的部分，从而节省带宽和时间。它支持本地和远程文件传输，常用于备份、同步和部署任务。  
  
  
鉴于漏洞危害较大，嘉诚安全提醒相关用户尽快更新至安全版本，避免引发漏洞相关的网络安全事件。  
  
  
**漏洞详情**  
  
  
  
  
  
  
  
  
1、CVE-2024-12084  
  
Rsync缓冲区溢出漏洞，经研判，该漏洞为**高危**漏洞。rsync守护进程中未正确处理攻击者控制的校验和长度（s2length），当MAX_DIGEST_LEN超过固定的SUM_LENGTH（16字节）时，攻击者可以在sum2缓冲区中写入越界数据，从而触发堆内存溢出问题。  
  
  
2、CVE-2024-12085  
  
Rsync信息泄露漏洞，经研判，该漏洞为  
**高危**漏洞。攻击者可通过操控校验和长度（s2length），引发与未初始化内存的比较，逐字节泄露栈数据。  
  
  
3、CVE-2024-12086  
  
Rsync文件泄露漏洞，经研判，该漏洞为**中危**漏洞。攻击者可构造校验和，逐字节枚举客户端任意文件内容。  
  
  
4、CVE-2024-12087  
  
Rsync路径遍历漏洞，经研判，该漏洞为  
**中危**漏洞。恶意服务器可利用符号链接绕过，将文件写入客户端的非目标目录。  
  
  
5、CVE-2024-12088  
  
Rsync路径遍历漏洞，经研判，该漏洞为  
**中危**漏洞。rsync在使用`--safe-links`选项时未正确验证符号链接目标，导致路径遍历漏洞，可能将文件写入非预期目录。  
  
  
6、CVE-2024-12747  
  
Rsync符号链接竞态条件漏洞，经研判，该漏洞为  
**中危**漏洞。攻击者可利用时机绕过默认行为，泄露敏感信息并可能导致权限提升。  
  
  
**危害影响**  
  
  
  
  
  
  
  
  
影响版本：  
  
CVE-2024-12084（缓冲区溢出漏洞）：3.2.7=  
  
CVE-2024-12085（信息泄露漏洞）：Rsync < 3.4.0  
  
CVE-2024-12086（文件泄露漏洞）：Rsync < 3.4.0  
  
CVE-2024-12087（路径遍历漏洞）：Rsync < 3.4.0  
  
CVE-2024-12088（路径遍历漏洞）：Rsync < 3.4.0  
  
CVE-2024-12747（符号链接竞态条件漏洞）：Rsync < 3.4.0  
  
  
**修复建议**  
  
  
  
  
  
  
  
  
目前该漏洞已经修复，请尽快下载并升级至最新版本  
  
下载链接：  
  
https://rsync.samba.org/download.html  
  
参考链接：  
  
https://www.openwall.com/lists/oss-security/2025/01/14/3  
  
https://kb.cert.org/vuls/id/952657  
  
https://nvd.nist.gov/vuln/detail/cve-2024-12084  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-12085  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-12086  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-12087  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-12088  
  
https://nvd.nist.gov/vuln/detail/CVE-2024-12747  
  
https://download.samba.org/pub/rsync/NEWS  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sDiaO8GNKJrLibWLtTwr4jgwpy3eH5PibzAg0GRWr2HPZo0pDjqjwEr79AS85PiablYCcYNwYrKTj955oiaSuW5Z0Ag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/sDiaO8GNKJrLftD6NkjwibfelSiaDSA8r1TnUsJzNguibKyupaNJsEgic28FoR6ROXp2XFyNticXHhFOibN80WcAKXvHw/640?wx_fmt=gif&from=appmsg "")  
  
  
