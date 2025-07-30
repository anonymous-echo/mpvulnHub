#  【安全圈】8220 利用 Log4Shell 漏洞进行挖矿   
 安全圈   2023-05-07 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
研究人员近日发现 8220 组织正在利用 Log4Shell 漏洞攻击 VMware Horizon 服务器，以便后续进行挖矿获利。受攻击的目标系统中包含韩国能源企业，由于系统存在漏洞且未打补丁，就被攻击者集火攻击。  
  
Log4Shell（CVE-2021-44228）是 Java 日志程序 Log4j 的远程代码执行漏洞，攻击者可以通过使日志中包含远程 Java 对象来执行。  
  
8220 团伙  
  
8220 团伙是一个针对 Windows 与 Linux 系统进行攻击的组织，自从 2017 年以来一直保持活跃。如果成功入侵系统，8220 主要通过挖矿来进行获利。该团伙不局限于特定地域，而是针对全球发起攻击。此前，8220 也利用 Atlassian Confluence 服务器的漏洞 CVE-2022-26134 等进行攻击。  
  
如果漏洞成功，攻击者会执行 PowerShell 命令来下载并执行后续的 PowerShell 脚本，最终安装门罗币矿机。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7N9cFHpjlJxQv99JsYDvEteuW8Ez0DywznwRIPQMZDo5xedx1jwhYzZQ/640?wx_fmt=jpeg "")  
  
利用 Atlassian Confluence 漏洞执行的 PowerShell 命令  
  
Fortinet 的研究人员近日发现 8220 开始利用 Oracle Weblogic 服务器的漏洞安装 ScrubCrypt。ScrubCrypt 是使用 .NET 开发的恶意软件，也提供安装其他恶意软件的能力。通常来说，ScrubCrypt 最终会安装门罗币矿机，这也是 8220 团伙的最终目标。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7Nta24xRRoPN5MnwXG5zYbria3icweWJh2tU8DmU3kqVI50ho2KbSg1Daw/640?wx_fmt=jpeg "")  
  
利用 Oracle Weblogic 漏洞攻击执行的 PowerShell 命令  
  
研究人员确认，8220 团伙近期一直在利用 Oracle Weblogic 漏洞以及 Log4Shell 漏洞下载 ScrubCrypt，随后通过 ScrubCrypt 安装门罗币矿机。  
  
Log4Shell 攻击  
  
自从 2021 年 12 月被披露以来，Log4Shell 漏洞已经被广泛利用。2022 年，Lazarus 组织也利用该漏洞发起攻击并传播 NukeSped 恶意软件。攻击者针对未打补丁的 VMware Horizon 中存在的 log4j 漏洞，该产品是用于远程工作与云基础架构的虚拟桌面解决方案。  
  
分析日志发现，ws_tomcatservice.exe 进程安装了 8220 团伙使用的门罗币矿机。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7N9GQVQP42uiahQNib2G5z0YgSseATo8MYU0MeII728qJsLiaCUTDP04csw/640?wx_fmt=jpeg "")  
  
通过 ws_tomcatservice.exe 进程执行的 PowerShell 命令  
  
没有完整的网络数据包，但从 VMware Horizon 的 ws_tomcatservice.exe 进程执行 PowerShell 命令与 8220 团伙常用的攻击方式来看，很可能是通过 Log4Shell 漏洞实现的攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NE6uayIKA6cDKvLyTW2uiaf1ibLy5NVpYeoNKzOYxB3iavh27SbyAAM4lA/640?wx_fmt=jpeg "")  
  
PowerShell 命令执行日志  
## ScrubCrypt 与 XMRig CoinMiner 分析  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NqcUGjygcmxtEY97qoDOia7pUWskd0oyWd9MhuDbbLtDPak36RvjOw4A/640?wx_fmt=jpeg "")  
  
恶意软件进程树  
  
利用 Log4Shell 漏洞攻击下载并执行的 PowerShell 脚本，脚本文件名为 bypass.ps1。尽管恶意软件的代码有所不同，但文件名称与功能基本类似。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NWicUiaBQgGWkXvwiaiaAU0bG6WxcfRQexkPePBpMiaOwmZsKeyYyFZwI1Vw/640?wx_fmt=jpeg "")  
  
bypass.ps1 PowerShell 脚本  
  
bypass.ps1 是带混淆的 PowerShell 脚本，简单去混淆后如下所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NN49XYOPxdrwyYlgIHVtBVTkViaF9Lokia45jaa4E71g1BSjv9H1N2ia4w/640?wx_fmt=jpeg "")  
  
PowerShell 脚本  
  
脚本首先绕过 AMSI，随后在 %TEMP%PhotoShop-Setup-2545.exe 路径中创建并执行内嵌的恶意软件。PhotoShop-Setup-2545.exe 是由 .NET 开发的 Downloader 类恶意软件，会下载恶意代码并将其注入 RegAsm.exe。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NibReicNByNpbBeHRO56mKfUMFfxv05KicOIVuq5PKvavibYSJGOHc8lqwQ/640?wx_fmt=jpeg "")  
  
.Net 恶意软件  
  
在 RegAsm.exe 进程中注入并执行的恶意软件经过混淆处理，但与 Fortinet 研究ScrubCrypt 的相似性来看，很可能是 ScrubCrypt 类型的恶意软件。用于攻击的 ScrubCrypt 中包含 3 个 C&C 的 URL 与 4 个端口（58001、58002、58003 和 58004）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NGX9WOzDkmm567WibFkQcfYmBRRfLsINUSzt72TnaNKOviaovVNTEZbSA/640?wx_fmt=jpeg "")  
  
ScrubCrypt（RegAsm.exe）的 C&C URL  
  
ScrubCrypt 连接到 C&C 服务器并下载其他恶意代码，实际中也发现了安装门罗币矿机的命令。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7N2GIcnmdibkFRX3V16yhV8F3x3urvUPFicWTJRLv1nSc6noRCPC7GvtxQ/640?wx_fmt=jpeg "")  
  
安装 XMRig CoinMiner 的 PowerShell 命令  
  
deliver1.exe 是用于下载并执行注入的恶意软件，将 ScrubCrypt 保存在 MSBuild.exe 的内部资源中。该 ScrubCrypt 中包含 2 个 C&C URL 与 4 个端口号（9090、9091、9092 和 8444）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NMibyCK3mtzLYX7XSlxkrfibz6rgzXkAoy09pdZSvP32vjR5FxYTQ0Xjw/640?wx_fmt=jpeg "")  
  
ScrubCrypt（MSBuild.exe）的 C&C URL  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NQ5husHokia78iaMWCv03y1Elq6b2ycDPWNQ8k8WtesviaUgK8zRzhmrEA/640?wx_fmt=jpeg "")  
  
恶意软件下载  
  
ScrubCrypt 会在注册表中增加：执行矿机时使用的配置数据（注入目标进程、矿池地址、钱包地址与矿机下载地址）、数据文件 plugin_3.dll、plugin_4.dll。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7Nj4eXibUHJvEjeCs5PJ6J3NxADj0t7y7YqRauZiaDQ1jz6fO7jhibDF0mg/640?wx_fmt=jpeg "")  
  
注册表数据  
  
plugin_4.dll 是一种经过编码的 .NET 恶意软件，其主要功能是解码 plugin_3.dll 文件。释放矿机，并将 plugin_3.dll 注入指定的良性进程 AddInProcess.exe。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgBRUia8tiankM9tnBLU7Kp7NCjGgXjpicTIuwAKnBBicJCBq4JsTOh2If2cgRtSxm6FdiaqYrHpqfTmag/640?wx_fmt=jpeg "")  
  
矿机注入的配置数据  
  
攻击者的门罗币钱包地址与之前发现针对 Atlassian Confluence 漏洞攻击、针对 Oracle Weblogic 漏洞攻击中所使用的门罗币地址相同，8220 团伙一直使用相同的钱包地址。  
  
结论  
  
8220 团伙针对未打补丁的系统发起攻击，安装门罗币矿机进行挖矿获利。该组织不仅针对存在漏洞的 Atlassian Confluence 发起攻击，也针对存在 Log4Shell 漏洞的 VMware Horizon 发起攻击。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliadrsGJibeME5m3zZhmtY2EXShKuiaELYQALu0wDGdFicwsa3bRxZvoOlrYOX2HW2WQ1YTmFzOW9GR2w/640?wx_fmt=png "")  
[【安全圈】智能家居设备侵犯个人隐私了吗?](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033800&idx=1&sn=a22d5d2f6e78136080acbde24a132e08&chksm=f36fff48c418765e620f693176f4a6437af20a22daf24a24868fa5a28a0b4e4fdc541fd11de5&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliadrsGJibeME5m3zZhmtY2EXRKMsur3MJ5xRDoibttTlGn3gRy9kMpicd38iboahkicU77Z556ibz8LRPtg/640?wx_fmt=png "")  
[【安全圈】实现95%模拟人声，AI语音诈骗日益猖獗](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033800&idx=2&sn=05a2d2fcebe9429fdd2c7d9f12a1d66b&chksm=f36fff48c418765e262631705552ed5b2e3a82305a275080d10349b64d2b5b3138fa647478bd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyliadrsGJibeME5m3zZhmtY2EXkY5ox2icQhjlpouCYibaZs5iaicja1WRlSGGEw2WXgvicoxL8yLCIgan6Jw/640?wx_fmt=jpeg "")  
[【安全圈】新的安卓恶意软件 "FluHorse "瞄准东亚市场](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033800&idx=3&sn=2547c15e25cd36d549cc488757c1f94b&chksm=f36fff48c418765eb8af2786b4890a67d4a8693f54f932c0b801db02eae6066309d9f91929e8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliadrsGJibeME5m3zZhmtY2EXCChZOugjOOmMjQ1JicyUXUQHDZ0EXl7LpAy7kgMCrElIxn2tAurbmaw/640?wx_fmt=png "")  
[【安全圈】因掩盖数据泄露，Uber前首席安全官被判三年缓刑](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033800&idx=4&sn=54ef469c94d7ea39f68575c10c3b830d&chksm=f36fff48c418765eee46a94185aadc890d07f10b6d9e0e98020350b9f633b0780f7382af4c30&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
  
  
