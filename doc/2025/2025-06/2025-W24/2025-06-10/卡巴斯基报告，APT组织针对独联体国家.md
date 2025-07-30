#  卡巴斯基报告，APT组织针对独联体国家  
会杀毒的单反狗  军哥网络安全读报   2025-06-10 01:01  
  
**导****读**  
  
  
  
一个名为“Librarian Ghouls”的高级持续性威胁 (APT) 组织进行了一场网络攻击活动，该组织针对俄罗斯和独联体国家，以窃取敏感数据并在受害者系统部署门罗币挖矿木马。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaHJp7dK93Fzfn52nicKpLweGn6FzStGQNHZibiaOezdbpXpPUJjojWUXbk8RYg1hKUbhI2icEYpINm1UA/640?wx_fmt=png&from=appmsg "")  
  
  
卡巴斯基研究人员称，最初的感染媒介涉及针对性的网络钓鱼电子邮件，其中携带受密码保护的存档文件，其中包含可执行有效负载。  
  
  
这些电子邮件看起来像是来自受信任组织的合法通信，附件伪装成官方文件PDF。感染链始于收件人打开存档文件，提取并运行其中的文件。有效载荷包含自动唤醒功能，可在当地时间凌晨 1 点将受害者的系统从睡眠模式唤醒，并允许攻击者远程访问系统四小时，直至凌晨 5 点系统恢复正常。  
  
  
据卡巴斯基称，自去年 12 月发起当前活动以来，攻击者已通过这种初始感染媒介感染了数百名受害者，主要是俄罗斯的工业组织和工程学校，其次是白俄罗斯和哈萨克斯坦。  
  
  
Librarian Ghoul 使用了合法的第三方软件，例如远程访问工具、压缩工具和 SMTP 实用程序，而非自定义恶意软件。其目标是让防御者更难发现和追踪。  
  
  
卡巴斯基在报告中表示：“所有恶意功能仍然依赖于安装程序、命令和 PowerShell 脚本。攻击者不断改进他们的攻击策略，不仅包括数据泄露，还包括部署远程访问工具以及使用钓鱼网站来窃取电子邮件帐户。”  
  
  
当受害者打开存档文件时，一个使用 Windows Smart Install Maker 实用程序构建的自解压安装程序就会部署到受害者系统上。主要有效载荷位于安装程序的配置文件中，并部署 Minimizer，这是一个合法的 Windows 实用程序，可以将应用程序最小化到系统托盘中，并在这种情况下隐藏恶意进程。  
    
  
  
然后，名为 rezet.cmd 的恶意批处理文件会与远程命令和控制 (C2) 服务器通信，并在受感染的系统上拉取六个合法应用程序，包括用于远程访问功能的 AnyDesk、用于通过 SMTP 进行电子邮件泄露的 Blat、用于禁用 Windows Defender 的 Defender Control 以及 PowerShell 唤醒脚本。  
  
  
另一个恶意批处理脚本 (bat.bat) 随后会通过 PowerShell 设置自动唤醒任务，禁用 Windows Defender，并运行合法实用程序创建计划任务，在凌晨 5 点关闭系统。  
  
  
恶意负载将数据打包成两个独立的存档，并通过 SMTP 发送到攻击者的 C2 服务器。  
  
  
最后，该批处理脚本会在受害者系统上部署 XMRig加密货币挖矿程序，安装用于管理挖矿程序并使其在系统中持久存在的组件，然后删除自身。  
  
  
Librarian Ghouls 在攻击中还部署了其他几种合法工具，包括用于监控受害者系统的名为 Mipko Personal Monitor 的 DLP 系统、名为 WebBrowserPassView 的密码恢复实用程序，以及用于执行操作系统相关任务的 NirCmd。  
  
  
Librarian Ghouls 绝不是唯一一个在攻击中使用合法第三方工具和 LotL 策略的组织。它完全摒弃了自定义恶意软件，这体现了 LotL 方法在帮助攻击者规避检测触发器和端点检测系统方面的有效性。  
  
  
由于 Librarian Ghouls 等组织使用的许多工具也常被管理员使用，因此区分恶意活动和良性活动对防御者来说变得更加困难。  
  
  
技术报告：  
  
https://securelist.com/librarian-ghouls-apt-wakes-up-computers-to-steal-data-and-mine-crypto/116536/  
  
  
新闻链接：  
  
https://www.darkreading.com/cyberattacks-data-breaches/librarian-ghouls-cyberattackers-strike  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
