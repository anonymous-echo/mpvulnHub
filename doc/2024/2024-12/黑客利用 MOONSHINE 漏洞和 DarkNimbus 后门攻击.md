#  黑客利用 MOONSHINE 漏洞和 DarkNimbus 后门攻击   
会杀毒的单反狗  军哥网络安全读报   2024-12-06 01:00  
  
**导****读**  
  
  
  
趋势科技在一篇分析报告中表示： “Earth Minotaur 使用 MOONSHINE 将 DarkNimbus 后门传送到 Android 和 Windows 设备，使其成为跨平台威胁。”  
  
  
“MOONSHINE 利用基于 Chromium 的浏览器和应用程序中的多个已知漏洞，要求用户定期更新软件以防止攻击。”  
  
  
Earth Minotaur 攻击的目标分布在澳大利亚、比利时、加拿大、法国、德国、印度、意大利、日本、尼泊尔、荷兰、挪威、俄罗斯、西班牙、瑞士、土耳其和美国。  
  
  
MOONSHINE于 2019 年 9 月首次曝光，公民实验室将其使用归咎于其追踪的名为POISON CARP 的运营商，该运营商与威胁组织Earth Empusa 和 Evil Eye有重叠。  
  
  
这是一种基于 Android 的漏洞利用工具包，已知利用各种 Chrome 浏览器漏洞来部署有效载荷，从而窃取受感染设备的敏感数据。  
  
  
具体来说，包含针对各种应用程序的代码，例如 Google Chrome、Naver 以及嵌入应用内浏览器的即时通讯应用程序（例如 LINE、QQ、微信和 Zalo）。  
  
  
根据趋势科技的说法，Earth Minotaur 与 Earth Empusa 没有直接联系。威胁组织使用升级版的 MOONSHINE 渗透受害者设备，随后用 DarkNimbus 感染它们。  
  
  
新变种增加了漏洞库CVE-2020-6418，这是 V8 JavaScript 引擎中的类型混淆漏洞，在有报道称该漏洞已被用作  
0day  
漏洞武器后，谷歌于 2020 年 2 月对其进行了修补。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFwCs0hTGpria4ofdqRDLfdOwzYGE1mu82pwiczPCbRudRsapue7HMMqzYxHUs03McbQrg0Hd98YOsA/640?wx_fmt=png&from=appmsg "")  
  
Earth Minotaur的攻击链  
  
  
研究人员表示：“Earth Minotaur 通过即时通讯应用发送精心设计的消息，诱使受害者点击嵌入的恶意链接。他们在聊天中伪装成不同的角色，以提高社交工程攻击的成功率。”  
  
  
这些虚假链接指向至少 55 个 MOONSHINE 漏洞工具包服务器之一，这些服务器负责在目标设备上安装 DarkNimbus 后门。  
  
  
为了巧妙欺骗，这些 URL 伪装成看似无害的链接。  
  
  
趋势科技表示：“当受害者点击攻击链接并被重定向到漏洞攻击包服务器时，它会根据嵌入的设置做出反应。攻击结束后，服务器会将受害者重定向到伪装的合法链接，以防止受害者注意到任何异常活动。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFwCs0hTGpria4ofdqRDLfdOibW5Z1VdnMoPre9KKNhzAxqUDiay9xgVm4v7JZU9W7RFMFCpoIxficG0w/640?wx_fmt=png&from=appmsg "")  
  
MOONSHINE 漏洞利用工具包的验证流程  
  
  
当基于 Chromium 的浏览器不易受到 MOONSHINE 支持的任何漏洞攻击时，该工具包服务器被配置为返回一个钓鱼页面，警告用户应用内浏览器（名为XWalk的 Android WebView 的定制版本）已过期，需要点击提供的下载链接进行更新。  
  
  
这会导致浏览器引擎降级攻击，从而允许威胁组织利用未修补的安全漏洞来利用 MOONSHINE 框架。  
  
  
成功的攻击会导致 XWalk 的木马版本植入 Android 设备并取代应用程序中的合法版本，最终为 DarkNimbus 的执行铺平道路。  
  
  
该后门据信自 2018 年以来就已开发并积极更新，它使用 XMPP 协议与攻击者控制的服务器进行通信，并支持详尽的命令列表来获取有价值的信息，包括设备元数据、屏幕截图、浏览器书签、电话通话记录、联系人、短信、地理位置、文件、剪贴板内容和已安装应用程序的列表。  
  
  
它还能够执行 shell 命令、录制电话、拍照，并滥用 Android 的辅助服务权限来收集来自 DingTalk、MOMO、QQ、Skype、TalkBox、Voxer、微信和 WhatsApp 的消息。  
  
  
最后但同样重要的是，它可以从受感染的手机上自行卸载。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFwCs0hTGpria4ofdqRDLfdObmHSD3r7icIZEAe9BPapM5PGHjSE4u0JHVQsGm0M7fQA60cQHuk7SjA/640?wx_fmt=png&from=appmsg "")  
  
MOONSHINE 漏洞攻击包所针对的漏洞和浏览器版本  
  
  
趋势科技表示，它还检测到了 Windows 版本的 DarkNimbus，该版本可能是在 2019 年 7 月至 10 月期间制作的，但直到一年多后的 2020 年 12 月才开始使用。  
  
  
它缺少 Android 版本的许多功能，但包含各种命令来收集系统信息、已安装应用程序的列表、击键、剪贴板数据、已保存的凭据和来自网络浏览器的历史记录，以及读取和上传文件内容。  
  
  
尽管目前尚不清楚Earth Minotaur的具体起源，但观察到的感染链的多样性，加上功能强大的恶意软件工具，表明这是一个复杂的威胁。  
  
  
趋势科技推测： “MOONSHINE 是一个仍在开发中的工具包，并已与多个威胁行为者共享，包括 Earth Minotaur、POISON CARP、UNC5221等。”  
  
  
技术报告：  
https://www.trendmicro.com/en_us/research/24/l/earth-minotaur.html  
  
  
新闻链接：  
  
https://thehackernews.com/2024/12/hackers-target-uyghurs-and-tibetans.html  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
