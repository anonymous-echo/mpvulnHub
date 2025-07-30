#  新的 OpenSSH 漏洞可能导致 Linux 系统以 Root 身份进行 RCE   
 网安百色   2024-07-07 19:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
OpenSSH 维护人员发布了安全更新，以修复一个严重的安全漏洞，该漏洞可能导致基于 glibc 的 Linux 系统中以 root 权限执行未经身份验证的远程代码。  
  
该漏洞代号为 regreSSHion，CVE 标识符为 CVE-2024-6387。它位于OpenSSH 服务器组件（也称为 sshd）中，用于监听来自任何客户端应用程序的连接。  
  
Qualys 威胁研究部门高级主管 Bharat Jogi 在今天发布的一份披露文件中表示：“该漏洞是 OpenSSH 服务器 (sshd) 中的信号处理程序竞争条件，允许在基于 glibc 的 Linux 系统上以 root 身份进行未经身份验证的远程代码执行 (RCE) 。该竞争条件会影响默认配置下的 sshd。”  
  
该网络安全公司表示，已发现至少 1400 万个暴露在互联网上的潜在易受攻击的 OpenSSH 服务器实例，并补充说，这是一个已修补的 18 年前的漏洞（跟踪号为CVE-2006-5051）的回归，该问题于 2020 年 10 月作为 OpenSSH 版本 8.5p1 的一部分重新出现。  
  
OpenSSH 在一份公告中表示：“已证明在具有 [地址空间布局随机化]的 32 位 Linux/glibc 系统上可成功利用该漏洞。在实验室条件下，攻击平均需要 6-8 小时的连续连接，直至达到服务器可接受的最大连接时长。”  
  
该漏洞影响 8.5p1 和 9.7p1 之间的版本。4.4p1 之前的版本也容易受到竞争条件漏洞的影响，除非它们针对 CVE-2006-5051 和CVE-2008-4109进行了修补。值得注意的是，OpenBSD 系统不受影响，因为它们包含阻止该漏洞的安全机制。  
  
该安全漏洞很可能也会影响 macOS 和 Windows，尽管其在这些平台上的可利用性仍未得到证实，需要进一步分析。具体来说，Qualys 发现，如果客户端在 120 秒内未进行身份验证（由 LoginGraceTime 定义的设置），则 sshd 的 SIGALRM 处理程序将以非异步信号安全的方式异步调用。  
  
利用 CVE-2024-6387 的最终结果是完全系统入侵和接管，使威胁行为者能够以最高权限执行任意代码、破坏安全机制、窃取数据，甚至保持持续访问。  
  
“漏洞一旦修复，又会在后续软件版本中再次出现，这通常是由于更改或更新无意中再次引入了该问题，”Jogi 说道。“这起事件凸显了彻底的回归测试在防止已知漏洞再次引入环境中的关键作用。”  
  
虽然该漏洞由于其远程竞争条件性质而存在重大障碍，但建议用户应用最新补丁以防范潜在威胁。还建议通过基于网络的控制来限制 SSH 访问，并实施网络分段以限制未经授权的访问和横向移动。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
