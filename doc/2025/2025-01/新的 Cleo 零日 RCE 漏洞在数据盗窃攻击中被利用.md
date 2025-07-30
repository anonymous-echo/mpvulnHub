#  新的 Cleo 零日 RCE 漏洞在数据盗窃攻击中被利用   
邑安科技  邑安全   2025-01-24 07:43  
  
更多全球网络安全资讯尽在邑安全  
  
  
黑客正在积极利用 Cleo 托管文件传输软件中的零日漏洞来破坏公司网络并进行数据盗窃攻击。  
  
该漏洞存在于该公司的安全文件传输产品 Cleo LexiCom、VLTrader 和 Harmony 中，该漏洞允许不受限制地上传和下载文件，从而导致远程代码执行。  
  
Cleo MFT 漏洞影响版本 5.8.0.21 及更早版本，是对先前修复的漏洞 CVE-2024-50623 的绕过，Cleo 于 2024 年 10 月解决了该漏洞。但是，该修复程序并不完整，允许威胁行为者绕过它并继续在攻击中利用它。  
  
Cleo 表示，全球有 4,000 家公司使用其软件，包括 TaylorMade、brother、New Balance、Hogan、Ryder 和 Duraflame。  
  
这些攻击让人想起之前在托管文件传输产品中利用零日漏洞的 Clop 数据盗窃攻击，包括 2023 年大规模利用 MOVEit Transfer、使用 GoAnywhere MFT 零日漏洞的攻击以及 2020 年 12 月对 Accellion FTA 服务器的零日漏洞利用。  
  
然而，网络安全专家 Kevin Beaumont 声称，这些 Cleo 数据盗窃攻击与新的 Termite 勒索软件团伙有关，该团伙最近入侵了全球许多公司使用的供应链软件提供商 Blue Yonder。  
  
“Termite 勒索软件组织运营商（可能还有其他组织）对 Cleo LexiCom、VLTransfer 和 Harmony 的零日漏洞利用，”Beaumont 在 Mastodon 上发帖。  
## 在野攻击  
  
Huntress 安全研究人员首先发现了对 Cleo MFT 软件的积极利用，他们还在一篇新的文章中发布了概念验证 （PoC） 漏洞，警告用户采取紧急行动。  
  
“这个漏洞正在被广泛利用，运行 5.8.0.21 的完全修补系统仍然可以被利用，”Huntress 解释说。  
  
“我们强烈建议您将任何暴露在 Internet 上的 Cleo 系统移动到防火墙后面，直到发布新补丁。”  
  
CVE-2024-50623 被积极利用的证据始于 2024 年 12 月 3 日，12 月 8 日观察到的攻击数量显著增加。  
  
尽管归因尚不清楚，但这些攻击与美国、加拿大、荷兰、立陶宛和摩尔多瓦的以下 IP 地址有关。  
  
```
176.123.5.126 - AS 200019 (AlexHost SRL) - Moldova 

5.149.249.226 - AS 59711 (HZ Hosting Ltd) - Netherlands 

185.181.230.103 - AS 60602 (Inovare-Prim SRL) - Moldova

209.127.12.38 - AS 55286 (SERVER-MANIA / B2 Net Solutions Inc) - Canada

181.214.147.164 - AS 15440 (UAB Baltnetos komunikacijos) - Lithuania

192.119.99.42  - AS 54290 (HOSTWINDS LLC) - United States
```  
  
  
这些攻击利用 Cleo 漏洞将名为“healthchecktemplate.txt”或“healthcheck.txt”的文件写入目标端点的“autorun”目录，这些文件由 Cleo 软件自动处理。  
  
发生这种情况时，这些文件会调用内置的导入功能来加载其他负载，例如包含 XML 配置 （'main.xml） 的 ZIP 文件，其中包含将要执行的 PowerShell 命令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1N39PtINn8tM7SPTq25L5R0icdWjDlvOphRZHpX5uj1ict3bsFg78PsHjJTSNqTNxQ5PvdvEpHuOFqgzibgEBkcOA/640?wx_fmt=png&from=appmsg "")  
  
利用在易受攻击的设备上执行 PowerShell 命令  
  
PowerShell 命令与远程 IP 地址建立回调连接，下载额外的 JAR 负载，并擦除恶意文件以阻碍取证调查。  
  
Huntress 表示，在漏洞利用后阶段，攻击者使用“nltest.exe”来枚举 Active Directory 域，部署 webshell 以在受感染的系统上进行持久远程访问，并使用 TCP 通道最终窃取数据。  
  
利用完系统后，威胁行为者会执行 PowerShell 命令从攻击中删除文件，例如“C：\LexiCom\cleo.1142”。  
  
Huntress 的遥测数据表明，这些攻击已经影响了至少 10 个使用 Cleo 软件产品的组织，其中一些组织从事消费品、食品行业、卡车运输和航运业务。  
  
Huntress 指出，在其可见性之外还有更多潜在受害者，Shodan 互联网扫描返回了 Cleo 软件产品的 390 个结果，绝大多数 （298） 易受攻击的服务器位于美国。  
  
Macnica 的威胁研究员 Yutaka Sejiyama 告诉 BleepingComputer，他的扫描为 Harmony 返回了 379 个结果，为 VLTrader 返回了 124 个结果，为 LexiCom 返回了 240 个结果。  
## 所需操作  
  
鉴于 CVE-2024-50623 的积极利用和当前补丁（版本 5.8.0.21）的无效性，用户必须立即采取措施降低泄露风险。  
  
Huntress 建议将暴露在 Internet 上的系统移动到防火墙后面，并限制对 Cleo 系统的外部访问。  
  
公司可以通过在目录“C：\LexiCom”、“C：\VLTrader”和“C：\Harmony”中查找可疑的 TXT 和 XML 文件来检查其 Cleo 服务器是否受到威胁，并检查日志以了解 PowerShell 命令执行情况。  
  
恶意 XML 文件将在 'hosts' 文件夹中找到，其中包含 bash（在 Linux 上）或 PowerShell（在 Windows 上）命令。Cleo 已经发布了适用于 Linux 和 Windows 的脚本，可以帮助找到这些恶意 XML 文件。  
  
最后Huntress 建议删除Harmony/VLTrader/Lexicom 下的任  
何“Cleo####.jar”文件，例如 cleo.5264.jar 或 cleo.6597.jar），因为它们可能是在利用漏洞期间上传的。  
  
此外，建议按照以下步骤关闭自动运行功能：  
1. 打开 Cleo 应用程序（LexiCom、VLTrader 或 Harmony）  
  
1. 导航到：其他窗格>配置>选项  
  
1. 清除标记为 Autorun Directory 的字段  
  
1. 保存更改  
  
Huntress 表示，Cleo 预计针对此漏洞的新安全更新将晚些时候发布。此外，有媒体向 Cleo 询问了有关该漏洞的其他问题，并被告知安全更新“正在开发中”。   
  
原文来自:   
bleepingcomputer.com  
  
原文链接: https://www.bleepingcomputer.com/news/security/new-cleo-zero-day-rce-flaw-exploited-in-data-theft-attacks/  
  
  
欢迎收藏并分享朋友圈，让五邑人网络更安全  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1N39PtINn8tD9ic928O6vIrMg4fuib48e1TsRj9K9Cz7RZBD2jjVZcKm1N4QrZ4bwBKZic5crOdItOcdDicPd3yBSg/640?wx_fmt=jpeg "")  
  
欢迎扫描关注我们，及时了解最新安全动态、学习最潮流的安全姿势！  
  
推荐文章  
  
1  
  
[新永恒之蓝？微软SMBv3高危漏洞（CVE-2020-0796）分析复现](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247488913&idx=1&sn=acbf595a4a80dcaba647c7a32fe5e06b&chksm=fa39554bcd4edc5dc90019f33746404ab7593dd9d90109b1076a4a73f2be0cb6fa90e8743b50&scene=21#wechat_redirect)  
  
  
2  
  
[重大漏洞预警：ubuntu最新版本存在本地提权漏洞（已有EXP）　](http://mp.weixin.qq.com/s?__biz=MzUyMzczNzUyNQ==&mid=2247483652&idx=1&sn=b2f2ec90db499e23cfa252e9ee743265&chksm=fa3941decd4ec8c83a268c3480c354a621d515262bcbb5f35e1a2dde8c828bdc7b9011cb5072&scene=21#wechat_redirect)  
  
  
  
  
  
