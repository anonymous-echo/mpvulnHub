#  即将被零信任取代？企业VPN屡屡曝安全漏洞   
 网络安全应急技术国家工程中心   2023-09-19 15:05  
  
你在日常工作生活中，是否曾使用过VPN？它或许曾帮助你轻松访问了一些突破地理限制的内容。但你知道吗？在使用的过程中，你很可能早已将自己的隐私暴露于“危险”之中。  
  
随着互联网的普及和信息安全的关注，VPN早已成为许多人保护在线隐私和安全的首选工具。然而，尽管VPN被广泛认可为一种安全性较高的上网方式，但其潜在的安全风险诸多，不可忽视。比如：  
  
传统VPN架构必须要对外暴露端口实现远程连接的功能，这很可能让所有互联网上的黑客或扫描器都能够轻而易举的攻击VPN站点。对于企业来说是一个严重的安全隐患，尤其体现在VPN爆出高危漏洞的时候。  
  
其次，VPN只针对用户进入身份做认证，缺少业务访问全周期的终端安全检测能力，使得访问过程存在巨大网络安全风险，病毒或攻击者很有可能通过VPN感染企业内部业务系统。不止如此，传统VPN还存在权限粗放风险大、安全漏洞频频爆雷等问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQCBvWt2ibtoLibeZz44oiakYKXHV0koyanHXtJb1Q0tqVj9hS5H8iadrE8A/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
随着现在企业上云趋势广泛应用，在多云、混合云环境下，VPN已经无能为力去保护非企业自建的云基础设施，甚至可以说为攻击者打开了大门。VPN不是通过线性访问来保护扁平网络，而是尝试保护外围网络。更大的问题是，VPN根本不够安全，无法抵御当今日益复杂的威胁。  
  
纵使调研机构Statista对2020年全球VPN市场规模的估计已达到了271亿美元，但技术变革的趋势，终究是不可阻挡的。  
  
时过境迁，彼时的“神器”VPN，此时已经面临着被全新“崛起”的零信任取代的“凉凉”命运。  
  
毕竟相比VPN接入后的“畅通无阻”，零信任的核心原则是“永不信任和始终验证”。相比传统vpn，很显然零信任的理念和架构才更符合当前的数字时代要求的网络安全范式。  
  
不过，让VPN走向今天这个“消亡”的结局，原因其实有很多。  
  
# VPN弊端暴露，安全问题愈演愈烈  
  
先来谈谈VPN存在的最核心问题——安全漏洞。其实VPN安全漏洞已经是一个老生常谈的话题了。这些年来因VPN漏洞导致的数据泄露新闻屡见不鲜。  
  
早在2019年，就有大量VPN服务器就被曝出重大漏洞，加剧了VPN网络安全态势的风险。  
  
其中，2019年4月，卡内基梅隆大学CERT/CC称，至少四款企业VPN应用中存在安全缺陷，包括思科、F5 Networks、Palo Alto Networks和Pulse Secure的VPN应用。这四款应用被证实以非加密形式将认证和/或会话cookie存储在计算机内存或日志文件中。  
  
而就在近日，VPN也曝出多个漏洞。比如思科自适应安全设备（Cisco Adaptive Security Appliance，ASA）和思科威胁防御系统（Cisco Firepower Threat Defense，FTD）中就曝出一个CVE-2023-20269漏洞 。且已经有勒索组织利用该漏洞对部分企业内部网络进行初始化访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQolj1syOD7RdBwfvZySsT4Jjibia8dSK1N8RMHuSYu7Dbg1O0RZlU7tbg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
9月8日，Atlas VPN 也曝出一个零日漏洞，该漏洞允许网站所有者查看 Linux 用户的真实 IP 地址。不久前，发现该漏洞的人在Reddit上公开发布了有关该零日漏洞的详细信息以及漏洞利用代码。  
  
由于该漏洞，恶意行为者可能会断开应用程序，从而断开用户与 VPN 网关之间的加密流量。这可能导致用户的 IP 地址泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQ2nFYI7kjmucweHShVKvy0cibegnByfM5AgibNzxxelf4e7e8r140O9yg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
非常值得一提的是，近日纽约大学和鲁汶大学的研究人员发现VPN存在多个“史诗级”漏洞，且时间长达二十余年，几乎所有VPN都“中招”。据悉，攻击者可利用这些漏洞读取用户流量、窃取用户信息，甚至攻击用户设备。  
  
根据研究结果显示，任何具有适当网络访问权限的人都可以通过漏洞实施攻击，且不受VPN安全协议限制。换而言之，无论VPN使用何种安全协议，所发现的漏洞都可能被滥用。即使是声称使用“军用级加密”或使用自行开发的加密协议的VPN（包括微软和苹果操作系统的内置VPN）也可能受到攻击。  
  
即使受害者使用了HTTPS加密， 攻击者也会泄露用户正在访问哪些网站，这可能会带来重大的隐私风险。  
  
研究者发现的四个普遍存在的VPN漏洞的CVE编号分别是：CVE-2023-36672、CVE-2023-35838、CVE-2023-36673和CVE-2023-36671。  
  
LocalNet攻击可能导致明文流量泄漏及流量阻塞  
  
第一对漏洞CVE-2023-36672、CVE-2023-35838可在LocalNet攻击中被利用。  
- CVE-2023-36672（参考CVSS分数为6.8）：LocalNet攻击导致明文流量泄漏  
  
- CVE-2023-35838（参考CVSS分数为3.1）：LocalNet攻击导致流量阻塞  
  
即当用户连接到攻击者设置的Wi-Fi或以太网时（下图）：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQGCJKQetKJgazaichmA4IShUndX2ibSUibxCNoibhuoa3v6KSglpIUNzZQA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
LocalNet攻击示意图  
  
后一对漏洞CVE-2023-36673、CVE-2023-36671可被攻击者或恶意互联网服务提供商(ISP)所利用，通过不受信任的Wi-Fi/以太网发动ServerIP攻击。  
- CVE-2023-36673（参考CVSS分数为7.4）：ServerIP攻击与DNS欺骗相结合，可以将流量泄漏到任意IP地址  
  
- CVE-2023-36671（参考CVSS分数为3.1）：ServerIP攻击，只有VPN服务器真实IP地址的流量才会被泄露  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQ6DlKDDVGT5ibAm4hpaC4UPCDcR0ia1ia0Kcxj3ia04CTowS3scic94dlsCA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
ServerIP攻击示意图  
  
据研究人员表示：上述的两种攻击都会操纵受害者的路由表，诱骗受害者将流量发送到受保护的VPN隧道之外，从而使对手能够读取和拦截传输的流量。  
  
除了数据泄露，此类攻击还产生另外一个风险：VPN通常用于保护较旧或不安全的协议，VPN防护失效意味着攻击者随后可以攻击较旧或不安全的协议，例如RDP、POP、FTP、telnet等。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQrjpnG6KuC1AAdxc099n1pnkgJ4SHuqJGyzxrz037zEHdG0vUF1ujTA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
另外，根据研究结果，大多数Windows、macOS和iOS的内置VPN客户端都容易受到攻击，超过三分之一的Linux上的VPN客户端也是如此。  
  
一直以来，VPN都因其能够在公用网络上建立专用网络，通过对数据包的加密和数据包目标地址的转换实现远程访问，所以在企业、政府机构远程办公中起着举足轻重的地位。  
  
这意味着，一旦VPN漏洞被黑客利用攻击，将面临巨大威胁。  
  
首先，黑客能够获取通过VPN传输的用户数据，包括个人身份信息、登录凭据、敏感文件等。这可能导致个人隐私泄露、身份盗窃或其他形式的欺诈活动。  
  
黑客还可利用VPN漏洞在用户系统中注入恶意软件、远程执行代码、进行拒绝服务攻击等。这可能导致系统崩溃、数据丢失或网络不可用。  
  
同时，黑客可能通过VPN漏洞访问受限资源、绕过认证控制、进一步侵入网络内部。这可能导致未授权的数据访问、设备被控制或网络受到进一步威胁。  
  
如果黑客成功利用VPN漏洞攻击企业或组织，可能导致负面的媒体报道、损害信任度，并对其声誉造成长期影响。  
  
因此，为了减少这些风险，最好及时更新VPN软件、采取强密码策略、启用多因素身份验证，并监测和修复任何已知的漏洞。同时，用户也应保持警惕，避免在不安全或不可信的网络上使用VPN。  
  
# VPN正在“消亡”，零信任正在“崛起”  
  
早年间，VPN是人们用来实现对本土分公司、国外总部的便捷访问，实现移动办公的利器。  
但面对日益复杂的网络环境与办公形态，传统VPN技术实现远程安全接入的方案带来了较大的挑战。  
  
不可否认，曾经的VPN确实站在“神坛”上，但是在大环境的变化之下，VPN也展现出了越来越多的安全弊病，不得不面临走向“消亡”的命运。  
  
而在这个过程中，零信任开始“崛起”。  
越来越多的安全厂商和企业都开始迈进了零信任时代。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQhlpLhN3n6Em5p1Fic35gFjS3jcYKs4icNyUSyqRsiayVHYeCiaoY8RgBGA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
零信任最早是在2010年的时候由Forrester Research的分析师John Kindervag提出，它既不是一种技术，也不是一个产品，而是一种安全理念和安全方法。  
  
零信任服务基于最小特权原则和持续身份验证的安全架构，摒弃了传统VPN中将信任集中在企业网络边缘的思想，将信任控制细化到每个用户和设备级别。  
  
相对于传统的VPN，零信任的优势有以下几点：  
- 一、零信任基于身份验证，要求用户和设备在每次访问时都进行验证，确保只有经过验证的用户和设备才能获得访问权限。这有助于防止未经授权的访问和身份伪造；  
  
- 二、零信任服务通过细粒度的访问控制策略，仅限定用户和设备能够访问的资源和功能。这种动态的策略决策可以根据用户的身份、设备的状态和环境的风险情况进行实时调整，提供更精细的安全保护；  
  
- 三、零信任服务支持多因素身份验证和单一登录（SSO）等先进的身份验证技术，增强身份验证的安全性。它还提供了对用户和设备行为的实时监测和分析，以便及时发现潜在的威胁和异常活动；  
  
- 四、零信任服务具有较高的可扩展性，可以适应企业复杂的网络环境和不断增长的用户数量。它可以与云服务、移动设备和第三方应用集成，为用户提供更灵活和便捷的访问体验；  
  
零信任与传统VPN安全模型的不同之处的核心就在于，它不断验证所有尝试访问网络的用户或设备，而VPN使用一次身份验证过程，并假设如果用户在网络内，一切都很安全。  
  
零信技术提供基于密码技术的零信任解决方案，实现零信任的五大安全目标中的网络身份可信、网络设备可信、网络流量加密、网络应用可信、网络数据加密，这五大目标都是通过采用密码技术的数字签名和加密来实现。每个用户都有可信身份证书，每个设备都有可信身份证书，用户使用可信身份和可信设备可以安全地通过互联网接入公司内网和接入云服务，而无需通过VPN设备。  
  
零信任从最初的雏形到具体的概念再到落地实践，已经历经了十余年的发展。  
  
如今企业越来越重视网络安全，所以很显然推动零信任的安全体系已经将被提上了日程。毋庸置疑，零信任时代已逐步开始显现。  
  
# 结语  
  
近年来，已有不少网络犯罪分子轮番推出了专门用于通过VPN获取敏感信息的钓鱼诈骗活动。由于VPN通常允许用户访问整个网络，涉及到很多设备信息和位置信息，因此一旦遭遇攻击，潜在的损害是巨大的。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibb9KrZIda6dzNEjHIuO8FQghjWsibrCcGlMjictE0JczEAicRauOoibpWYH09VGNyxMlCxIvB8qZCLFA/640?wx_fmt=jpeg "")  
  
图片来源网络  
  
虽然目前我们并不确定未来VPN是否会被零信任或其他新型技术所取代，但可以确定的是，在当下复杂的使用场景和网络环境下，企业IT边界越发模糊不清，面对这种现状，VPN确实有点捉襟见肘了。VPN“凉凉”，或许真的只是时间问题罢了。  
  
**参考资料：**  
  
https://www.secrss.com/articles/57826  
  
https://zhuanlan.zhihu.com/p/642763718  
  
https://baijiahao.baidu.com/s?id=1653408593792201381&wfr=spider&for=pc  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
