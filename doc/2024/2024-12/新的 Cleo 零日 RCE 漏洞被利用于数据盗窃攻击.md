#  新的 Cleo 零日 RCE 漏洞被利用于数据盗窃攻击   
Rhinoer  犀牛安全   2024-12-16 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmBnHjyJjYQp7pPngDZlB4kz71ibU3etJRKJCtZdIJiafjnaqHugzHEMjPDibNO2mnzfica3bibEBMlvmA/640?wx_fmt=png&from=appmsg "")  
  
黑客正在积极利用 Cleo 管理文件传输软件中的零日漏洞来入侵公司网络并进行数据盗窃攻击。  
  
该漏洞存在于该公司的安全文件传输产品 Cleo LexiCom、VLTrader 和 Harmony 中，该漏洞允许不受限制的文件上传和下载，从而导致远程代码执行。  
  
Cleo MFT 漏洞影响 5.8.0.21 及更早版本，是之前修复的漏洞 CVE-2024-50623 的绕过方法，Cleo于 2024 年 10 月解决了该漏洞。然而，修复并不完整，攻击者可以绕过该漏洞并继续利用它进行攻击。  
  
Cleo 表示，其软件已被全球 4,000 家公司使用，包括 Target、沃尔玛、Lowes、CVS、家得宝、联邦快递、Kroger、Wayfair、Dollar General、Victrola 和 Duraflame。  
  
这些攻击让人想起了之前利用托管文件传输产品零日漏洞的 Clop 数据盗窃攻击，包括2023 年对 MOVEit Transfer 的大规模利用、使用GoAnywhere MFT 零日漏洞的攻击，以及 2020 年 12 月 对 Accellion FTA 服务器的零日漏洞利用。  
  
然而，网络安全专家 Kevin Beaumont 声称，这些 Cleo 数据盗窃攻击与新的 Termite 勒索软件团伙有关，该团伙最近入侵了全球多家公司使用的供应链软件提供商Blue Yonder 。  
  
Beaumont 在Mastodon上发帖称：“Termite 勒索软件组织（可能还有其他组织）发现了针对 Cleo LexiCom、VLTransfer 和 Harmony 的零日漏洞。”  
  
在野攻击  
  
Huntress 安全研究人员首次发现了Cleo MFT 软件的主动攻击，他们还在一篇新文章中发布了概念验证 (PoC) 漏洞，警告用户采取紧急行动。  
  
Huntress 解释道：“该漏洞正在被广泛利用，运行 5.8.0.21 的完全修补系统仍然可以被利用。”  
  
我们强烈建议您将任何暴露在互联网上的 Cleo 系统移到防火墙后面，直到新的补丁发布。  
  
有证据表明， CVE-2024-50623被积极利用始于 2024 年 12 月 3 日，12 月 8 日观察到的攻击量显著上升。  
  
虽然攻击原因尚不清楚，但这些攻击与美国、加拿大、荷兰、立陶宛和摩尔多瓦的以下 IP 地址有关。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmBnHjyJjYQp7pPngDZlB4kO3ic3n4Arpialt90zPBoJzrmJZQ9toNR6VUD7hvXicLSibOpI1J9EIDd8g/640?wx_fmt=png&from=appmsg "")  
  
攻击利用 Cleo 漏洞将名为“healthchecktemplate.txt”或“healthcheck.txt”的文件写入目标端点的“autorun”目录，这些文件由 Cleo 软件自动处理。  
  
当发生这种情况时，文件会调用内置的导入功能来加载其他有效负载，例如包含 XML 配置（“main.xml”）的 ZIP 文件，其中包含将要执行的 PowerShell 命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBmBnHjyJjYQp7pPngDZlB4kQgZO71KMx94dDmYibagBSHOWuvx57ac8RK1ddSAXtibc5ibpQy2iazmZxA/640?wx_fmt=png&from=appmsg "")  
  
PowerShell 命令与远程 IP 地址建立回调连接、下载额外的 JAR 负载并擦除恶意文件以阻碍法医调查。  
  
Huntress 表示，在后利用阶段，攻击者使用“nltest.exe”枚举 Active Directory 域，部署 webshell 以在受感染系统上进行持久远程访问，并使用 TCP 通道最终窃取数据。  
  
当完成对系统的利用后，威胁行为者会执行 PowerShell 命令来删除攻击中的文件，例如“C:\LexiCom\cleo.1142”。  
  
Huntress 的测试表明，这些攻击影响了至少十个使用 Cleo 软件产品的组织，其中一些组织从事消费品、食品行业、卡车运输和航运业务。  
  
Huntress 指出，在其可见范围之外还有更多的潜在受害者，Shodan 互联网扫描返回了 390 个 Cleo 软件产品的结果，绝大多数（298 个）易受攻击的服务器位于美国。  
  
Macnica 威胁研究员 Yutaka Sejiyama 告诉 BleepingComputer，他的扫描结果为 Harmony 返回 379 条结果，为 VLTrader 返回 124 条结果，为 LexiCom 返回 240 条结果。  
  
需要采取的行动  
  
鉴于 CVE-2024-50623 的活跃利用以及当前补丁（版本 5.8.0.21）的无效性，用户必须立即采取措施降低受到攻击的风险。  
  
Huntress 建议将暴露在互联网上的系统移到防火墙后面，并限制对 Cleo 系统的外部访问。  
  
公司可以通过查找目录“C:\LexiCom”、“C:\VLTrader”和“C:\Harmony”中的可疑 TXT 和 XML 文件来检查其 Cleo 服务器是否受到攻击，并检查 PowerShell 命令执行日志。  
  
恶意 XML 文件位于“hosts”文件夹中，其中包含 bash（在 Linux 上）或 PowerShell（在 Windows 上）命令。Cleo 发布了适用于Linux和Windows 的脚本，可帮助查找这些恶意 XML 文件。  
  
最后，Huntress 建议删除 Harmony/VLTrader/Lexicom 下的任何“Cleo####.jar”文件（例如 cleo.5264.jar 或 cleo.6597.jar），因为它们很可能是在利用漏洞期间上传的。  
  
此外，建议按照以下步骤关闭自动运行功能：  
1. 打开 Cleo 应用程序（LexiCom、VLTrader 或 Harmony）  
  
1. 导航至：配置 > 选项 > 其他窗格  
  
1. 清除标有自动运行目录的字段  
  
1. 保存更改  
  
Huntress 表示，Cleo 预计本周晚些时候将发布针对此漏洞的新安全更新。  
  
BleepingComputer 向 Cleo 询问了有关该漏洞的更多问题，并被告知安全更新“正在开发中”。  
  
Cleo 告诉 BleepingComputer：“我们在 Cleo Harmony、VLTrader 和 LexiCom 产品中发现了一个严重漏洞。在发现漏洞后，我们立即在外部网络安全专家的协助下展开了调查，将此问题通知  
了客户，并提供了客户应立即采取的缓解措施，以便在开发补丁程序的同时解决漏洞。”  
  
我们的调查仍在进行中。我们鼓励客户定期查看 Cleo 的安全公告网页以获取更新。Cleo 仍然专注于支持其客户，并为那些需要额外技术帮助来解决此漏洞的客户提供了增强的全天候客户支持服务。  
  
  
信息来源：BleepingComputer  
  
