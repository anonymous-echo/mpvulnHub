#  新的僵尸网络利用 NVR、TP-Link 路由器中的漏洞   
会杀毒的单反狗  军哥网络安全读报   2024-12-25 01:00  
  
**导****读**  
  
  
  
一种新的基于 Mirai 的僵尸网络正在积极利用远程代码执行漏洞，该漏洞尚未得到  
CVE  
编号，也没有在 DigiEver DS-2105 Pro NVR 中修补。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaEODJ4BJZ33A6xhOibOvWNnfS0ibPia3ia1AVkAibHeSb9ANfmcLyyqLbe9W1AtCibymWQEgnL7IM1jehDw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
僵尸网络针对多个网络录像机和固件过时的 TP-Link 路由器。  
  
  
TXOne 研究员 Ta-Lun Yen 记录了该活动所利用的漏洞之一，并于去年在罗马尼亚布加勒斯特举行的 DefCamp 安全会议上进行了展示。该研究员当时表示，该问题影响了多台 DVR 设备。  
  
  
Akamai 的研究人员观察到，僵尸网络在 11 月中旬开始利用该漏洞，但发现证据表明该活动至少从 9 月份就开始活跃。  
  
  
除了 DigiEver 漏洞之外，新的 Mirai 恶意软件变种还针对TP-Link 设备上的CVE-2023-1389和 Teltonika RUT9XX 路由器上的 CVE-2018-17532。  
  
### 针对 DigiEver NVR 的攻击  
###   
  
被用来攻击 DigiEver NVR 的漏洞是一个远程代码执行 (RCE) 缺陷，黑客的目标是“/cgi-bin/cgi_main.cgi”URI，该 URI 会不正确地验证用户输入。  
  
  
这允许远程未经身份验证的攻击者通过某些参数（例如 HTTP POST 请求中的 ntp 字段）注入“curl”和“chmod”等命令。  
  
  
Akamai 表示，它所看到的基于 Mirai 的僵尸网络发起的攻击与 Ta-Lun Yen 演示中描述的攻击类似。  
  
  
通过命令注入，攻击者从外部服务器获取恶意软件二进制文件，并将设备纳入其僵尸网络。通过添加 cron 作业实现持久性。  
  
  
一旦设备受到攻击，就会利用漏洞集和凭证列表进行分布式拒绝服务 (DDoS) 攻击或传播到其他设备。  
  
  
Akamai 表示，新的 Mirai 变种因使用 XOR 和 ChaCha20 加密以及针对包括 x86、ARM 和 MIPS 在内的广泛系统架构而著称。  
  
  
Akamai 评论道：“尽管采用复杂的解密方法并不是什么新鲜事，但它表明基于 Mirai 的僵尸网络运营商的策略、技术和程序正在不断发展。”  
  
  
研究人员表示：“这一点尤其值得注意，因为许多基于 Mirai 的僵尸网络仍然依赖于原始 Mirai 恶意软件源代码版本中包含的回收代码中的原始字符串混淆逻辑。”  
  
  
研究人员指出，该僵尸网络还利用了 Teltonika RUT9XX 路由器中的漏洞CVE-2018-17532以及影响 TP-Link 设备的漏洞CVE-2023-1389 。  
  
  
技术报告：  
  
https://www.akamai.com/blog/security-research/digiever-fix-that-iot-thing  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/new-botnet-exploits-vulnerabilities-in-nvrs-tp-link-routers/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
