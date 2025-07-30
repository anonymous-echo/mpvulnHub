#  新的 OpenSSH 漏洞使 SSH 服务器面临 MitM 攻击和拒绝服务攻击的风险   
胡金鱼  嘶吼专业版   2025-04-02 14:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
OpenSSH 发布了安全更新，修复了两个漏洞，一个是 MitM 攻击漏洞，另一个是拒绝服务漏洞，其中一个漏洞是在十多年前引入的。Qualys 发现了这两个漏洞，并向 OpenSSH 的维护人员展示了其可利用性。  
  
OpenSSH（开放安全外壳）是 SSH（安全外壳）协议的一个免费开源实现，它为不安全网络上的安全远程访问、文件传输和隧道传输提供加密通信。  
  
作为世界上最广泛使用的工具之一，在企业环境、信息技术、开发运维、云计算和网络安全应用中，基于 Linux 和 Unix（包括 BSD、macOS）的系统中有着很高的采用率。  
# 两个漏洞  
  
根据 CVE-2025-26465 跟踪的 MiTM 漏洞是在2014年12月发布 OpenSSH 6.8p1 时引入的，因此该问题在十多年内未被发现。  
  
当启用“VerifyHostKeyDNS”选项时，该漏洞会影响 OpenSSH 客户端，允许威胁者执行 MitM 攻击。  
  
无论 VerifyHostKeyDNS 选项设置为“yes”还是“no”，针对 OpenSSH 客户端（CVE-2025-26465）的攻击都能成功，不需要用户交互，也不依赖于 DNS 中是否存在 SSHFP 资源记录（SSH指纹）。  
  
启用后，由于错误处理不当，攻击者可以通过在验证期间强制出现内存不足错误来欺骗客户端接受非法服务器的密钥。  
  
通过拦截 SSH 连接并提供带有过多证书扩展的大 SSH 密钥，攻击者可以耗尽客户端的内存，绕过主机验证，劫持会话以窃取凭据、注入命令和泄露数据。  
  
虽然“VerifyHostKeyDNS”选项在 OpenSSH 中默认是禁用的，但从2013年到2023年，它在 FreeBSD 上默认是启用的，这使得许多系统暴露在这些攻击之下。  
  
第二个漏洞是 CVE-2025-26466，这是2023年8月发布的 OpenSSH 9.5p1 中引入的预认证拒绝服务漏洞。  
  
这个问题源于密钥交换期间不受限制的内存分配，从而导致不受控制的资源消耗。  
  
攻击者可以重复发送16字节的 ping 消息，这会迫使 OpenSSH 缓冲256字节的响应，而不会立即受到限制。  
  
在密钥交换期间，这些响应将被无限期存储，从而导致内存消耗过多和 CPU 过载，从而可能导致系统崩溃。  
  
利用 CVE-2025-26466 的后果可能没有第一个漏洞那么严重，但在身份验证之前利用它的事实保持了非常高的中断风险。  
# 发布安全更新  
  
OpenSSH 团队本周发布了9.9p2版本，解决了这两个漏洞，因此建议相关用户应尽快迁移到该版本。此外，除非绝对必要，建议禁用 VerifyHostKeyDNS ，并依靠手动密钥指纹验证来确保 SSH 连接的安全。  
  
对于 DoS 问题，建议管理员执行严格的连接速率限制，并监控 SSH 流量的异常模式，以便及早阻止潜在的攻击。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/new-openssh-flaws-expose-ssh-servers-to-mitm-and-dos-attacks/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibukbqgaubuZyap9icD53z2pHNzVWDsW4XvjltwDJNybxuGyyks1RxqQrPqkARsuBFm6ib0KPXY8CeQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibukbqgaubuZyap9icD53z2pyrL5z1DhJVIAiaVF4Aq1iaJuiaZiaV6S8uNQsBrQULiaVJep8iarL2qIg8Nw/640?wx_fmt=png&from=appmsg "")  
  
  
