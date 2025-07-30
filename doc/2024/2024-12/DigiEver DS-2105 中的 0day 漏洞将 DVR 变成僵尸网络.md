#  DigiEver DS-2105 中的 0day 漏洞将 DVR 变成僵尸网络   
 独眼情报   2024-12-26 02:01  
  
数字攻击从挡风玻璃下开始。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnTI80TfMIWSpibtFBvjiamD5icZFookiaRt2UWErnmiadhqmqT8V7vGNN8QtOAWMXZjE5wsda4AMZuQYbA/640?wx_fmt=jpeg&from=appmsg "")  
  
网络安全研究人员发现了一个新的基于Mirai的僵尸网络，该网络正在积极利用DigiEver DS-2105 Pro DVR 中的远程代码执行漏洞。该漏洞属于零日漏洞，尚未分配 CVE，且尚未发布修复程序。这一事实使得受害者的设备很容易成为黑客的目标。  
  
该网络攻击始于 10 月份，影响了各种 软件过时的TP-Link 网络录像机和路由器。TXOne 研究员 Ta-Lun Yen 在布加勒斯特的 DefCamp 会议上提出了该活动中使用的漏洞之一 。据他介绍，该问题影响了许多 DVR 设备。  
  
Akamai自 11 月中旬以来就 检测到该漏洞被积极利用 ，但有证据表明攻击早在 9 月份就开始了。除了 DigiEver 之外，该僵尸网络还针对 TP-Link 设备中的漏洞CVE-2023-1389和 Teltonika RUT9XX 路由器中的 漏洞 CVE-2018-17532 。  
  
DigiEver 设备漏洞利用了“/cgi-bin/cgi_main.cgi”URI 处理中的错误，该错误无法正确验证用户数据。这使得未经身份验证的攻击者可以通过 HTTP 请求参数（例如 ntp 字段）远程注入诸如curl 和 chmod 之类的命令。  
  
黑客使用命令注入从外部服务器下载恶意文件，然后将设备连接到僵尸网络。添加 Cron 作业以维持访问。受感染的设备用于执行DDoS攻击或进一步传播僵尸网络。  
  
新版本的 Mirai 因其使用 XOR 和 ChaCha20 加密以及对多种架构的支持（包括 x86、ARM 和 MIPS）而脱颖而出。Akamai 表示，这表明僵尸网络运营商的运营方式发生了变化。  
  
这些网络中的大多数仍然使用 Mirai 原始源代码中的原始加密算法。然而，ChaCha20 等新方法表明威胁级别有所增加。Akamai 报告还提供了妥协指标 (IoC) 和 Yara 规则，有助于检测和阻止此威胁。  
  
现代僵尸网络表现出日益增强的复杂性和适应性，将每个漏洞变成大规模攻击的工具。正确构建的数字防御不仅需要及时更新，还需要主动的威胁分析。  
  
  
