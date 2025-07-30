#  Helldown 勒索软件利用 Zyxel 防火墙的 VPN 漏洞入侵公司网络   
Rhinoer  犀牛安全   2024-12-24 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrFUxAK8tjFS4JPEkSaQV0agWHBFLaw3NuFQlaJibtwx1arkql8GqeX7w/640?wx_fmt=png&from=appmsg "")  
  
据信，新的“Helldown”勒索软件行动针对的是 Zyxel 防火墙的漏洞，以侵入公司网络，从而窃取数据并加密设备。  
  
根据最近对 Helldown 攻击的观察，法国网络安全公司Sekoia报告了这一情况。  
  
尽管 Helldown 并不是勒索软件领域的主要参与者，但自从今年夏天推出以来，其发展迅速，其数据勒索门户网站上列出了众多受害者。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrL2ZWYGkzoxNT6dMHOocibH0p9sF0Y8K16uVcbxRQaKTotfobnechzvA/640?wx_fmt=png&from=appmsg "")  
  
Helldown 介绍  
  
Helldown于 2024 年 8 月 9 日首次由 Cyfirma 记录，随后10 月 13 日Cyberint再次记录，均简要描述了新的勒索软件操作。  
  
10 月 31 日，360NetLab 安全研究员 Alex Turing 首次报告了针对 VMware 文件的 Helldown 勒索软件 Linux 变种。  
  
Linux 变体具有列出和终止虚拟机以加密图像的代码，但其功能仅被部分调用，表明它可能仍在开发中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrXXNRmsjqkTK5siaYic2OaERRTiaS6uQuutsSgjLL3nwoxAAgk1m55nDWQ/640?wx_fmt=png&from=appmsg "")  
  
Sekoia 报告称，Helldown for Windows 基于泄露的 LockBit 3 构建器，其操作与 Darkrace 和 Donex 相似。然而，根据现有证据，无法确定两者之间的确切联系。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrnynNPg9HZumkGDDeyuazEKcwasyAUzicCq6LB5h6vibLAibALwD8Tvl5g/640?wx_fmt=png&from=appmsg "")  
  
截至 2024 年 11 月 7 日，该威胁组织在其最近更新的勒索门户网站上列出了 31 名受害者，主要是总部位于美国和欧洲的中小型公司。截至今天，这一数字已降至 28 人，这可能表明其中一些人已经支付了赎金。  
  
塞科亚表示，Helldown 在窃取数据方面并不像其他组织那样有选择性，而是采取更有效的策略，并在其网站上发布大型数据包，有一次数据包高达 431GB。  
  
列出的受害者之一是网络和网络安全解决方案提供商 Zyxel Europe。  
  
该组织的加密器似乎并不是很先进，威胁行为者使用批处理文件来结束任务，而不是将此功能直接合并到恶意软件中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHricGCLlgPpxTOhNsKfibTFUK33CQtcQEaF6gNuHpGHR4ibWf4v5aL7fkMg/640?wx_fmt=png&from=appmsg "")  
  
在加密文件时，威胁者会生成一个随机的受害者字符串，例如“FGqogsxF”，该字符串将用作加密文件的扩展名。勒索信也会在其文件名中使用这个受害者字符串，例如“Readme.FGqogsxF.txt”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrjibbPOicmjicbTXWlJZSIMtWic2eG3Qk22ZVc4lw1yGdMWFOBbIElvakrQ/640?wx_fmt=png&from=appmsg "")  
  
指向 Zyxel 漏洞的证据  
  
Sekoia 根据 Zyxel Europe 的线索发现，Helldown 网站上列出的至少 8 名受害者在遭到入侵时使用 Zyxel 防火墙作为 IPSec VPN 接入点。  
  
接下来，Sekoia 注意到 11 月 7 日的一份Truesec 报告提到在 Helldown 攻击中使用了一个名为“OKSDW82A”的恶意帐户，并且还使用了一个配置文件（“zzz1.conf”）作为针对基于 MIPS 的设备（可能是 Zyxel 防火墙）的攻击的一部分。  
  
攻击者使用该帐户通过 SSL VPN 建立与受害者网络的安全连接、访问域控制器、横向移动并关闭端点防御。通过进一步调查，Sekoia 在 Zyxel 论坛上发现了创建可疑用户帐户“OKSDW82A”和配置文件“zzz1.conf”的报告，设备管理员报告他们正在使用固件版本 5.38。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHr9puRYIQrvauEpbUqe5DnOfQUawwMb3iam1F4kSEZIZ8Y9WSc4Ibqg4Q/640?wx_fmt=png&from=appmsg "")  
  
根据该版本，Sekoia 的研究人员推测 Helldown 可能正在使用 CVE-2024-42057，这是 IPSec VPN 中的命令注入，允许未经身份验证的攻击者在基于用户的 PSK 模式下使用精心设计的长用户名执行 OS 命令。  
  
此外，Sekoia 还考虑了 Zyxel 上一个未记录的漏洞，并将其详细信息与该供应商的 PSIRT 分享。  
  
CVE-2024-42057已于 9 月 3 日随着固件版本 5.39 的发布而修复，目前利用细节尚未公开，因此 Helldown 被怀疑可以利用私有的 n-day 漏洞。  
  
此外，  
Sekoia 研究员 Jeremy Scion  还发现了 10 月 17 日至 22 日期间从俄罗斯上传到 VirusTotal 的有效载荷，但有效载荷并不完整。它包含一个 base64 编码的字符串，解码后会显示 MIPS 架构的 ELF 二进制文件。然而，有效载荷似乎并不完整。Sekoia 评估，该文件很可能与前面提到的 Zyxel 入侵有关。”  
  
BleepingComputer 就这些攻击的问题联系了 Zyxel，Zyxel最新发布的一份公告表示，解决了 Sekoia 报告中引发的担忧，并向客户保证固件版本 5.39 可以抵御这些攻击。  
  
  
信息来源：  
BleepingComputer  
  
