#  发现与 IXON VPN 客户端相关的三个新漏洞，可导致本地权限提升 (LPE)   
 Ots安全   2025-05-27 04:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
本文详细披露了瑞典网络安全公司 Shelltrail 发现的 IXON VPN 客户端中的三个新漏洞（CVE-2025-ZZZ-01、CVE-2025-ZZZ-02 和 CVE-2025-ZZZ-03），这些漏洞可能导致 Windows 和 Linux 系统上的本地权限提升（LPE）。  
  
  
文章深入分析了漏洞的成因：Linux 系统上的 CVE-2025-ZZZ-02 利用了可预测的临时文件路径（/tmp/vpn_client_openvpn_configuration.ovpn），通过创建命名管道注入恶意 OpenVPN 配置实现 root 权限执行；Windows 系统上的 CVE-2025-ZZZ-03 则利用 C:\Windows\Temp 目录中的竞争条件，允许攻击者覆盖配置文件以获得 SYSTEM 权限。  
  
  
IXON 已通过将临时文件移至高权限目录的方式，在 1.4.4 版本中修复了 LPE 问题，但第三个漏洞（CVE-2025-ZZZ-01）尚未公开修复细节。  
  
  
文章还提供了漏洞的技术细节、攻击演示及修复建议，旨在帮助工业系统用户防范潜在的网络安全威胁。  
  
本文将介绍在 IXON VPN 客户端中发现的三个新漏洞 CVE-2025-ZZZ-01、CVE-2025-ZZZ-02 和 CVE-2025-ZZZ-03。这些漏洞会导致 Windows 和 Linux 系统上的本地权限提升，此外还有一个相当有趣的 [已编辑]。  
  
已为这些漏洞申请 CVE ID，但由于资金有限且 MITRE 工作积压，目前尚未分配。CVE ID 分配完成后，本文将立即更新。  
  
请继续关注以获取完整披露信息。  
  
背景  
  
欢迎光临，祝您咖啡温暖，当地天气宜人等等。在最近的一次安全评估中，Shelltrail 通过云 VPN 提供商 IXON 获得了访问环境的权限。IXON 是一家荷兰公司，专门从事工业系统设备和远程访问。  
  
要使用 IXON VPN，用户必须购买物理远程访问设备，并通过以太网将其连接到网络。IXON 设备通过以太网或移动数据提供的互联网连接到云环境。安装和设置完成后，用户可以访问云门户建立 VPN 连接，从而安全地访问部署设备的本地网络。  
  
至少对于渗透测试人员来说，现在需要解答许多问题，然后才能安然入睡。  
  
引擎盖下  
  
因此，为了连接到 IXON VPN 设备，必须安装其专有的 VPN 客户端。此客户端的下载地址与https://ixon.cloud用户启动 VPN 连接的位置相同。此云门户要求用户提供用户名和密码（以及额外的 MFA），并且必须邀请用户访问特定的 IXON VPN 设备。  
  
https://ixon.cloud 所以我们现在知道网页和本地安装的 VPN 客户端之间必须发生某种交互。  
  
通过枚举已安装的VPN客户端，我们发现一个本地Web服务器正在运行https://localhost:9250。我们发现这是一个自定义编译的C二进制文件，它为VPN客户端启用了本地用户配置选项。  
  
```
$ file /etc/ixon/vpn_client/vpn_client/etc/ixon/vpn_client/vpn_client: ELF 64-bit LSB pie executable, x86-64, version1 (GNU/Linux), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=032477110a2d9103328159ac17cbf0bdf18f9b91, stripped
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeE4A70ZJcGMWKhyvy6SjkWjTegU5KlJibx4r5ExWiborAfR2hD7olsyWe3HLTUbwcPZo3J0doZia8Tg/640?wx_fmt=png&from=appmsg "")  
  
这vpn_client至少在 Linux 上作为 systemd 服务运行：  
  
```
$ systemctl status ixon_vpn_client.service? ixon_vpn_client.service - VPN Client (IXON Remote Service)     Loaded: loaded (/etc/systemd/system/ixon_vpn_client.service; enabled; preset: disabled)     Active: active (running) since Tue 2025-01-2810:17:54 CET; 3 weeks 0 days agoInvocation:5ccedc9d3ed4485983755fcba25deae0   Main PID:113045 (vpn_client)      Tasks:8 (limit:16628)     Memory:10.8M (peak:13.6M)        CPU:645ms     CGroup: /system.slice/ixon_vpn_client.service             ??113045 /etc/ixon/vpn_client/vpn_client
```  
  
  
并且它以 root 身份运行：  
```
$ ps auxww | grep vpn_clientroot 113045  0.0  0.174784416976 ? Ssl 00:22   0:00 /etc/ixon/vpn_client/vpn_client
```  
  
  
例如，此 Web UI 允许本地用户设置代理服务器、指定 VPN 连接类型、修改 OpenVPN TAP 适配器设置或更改 Web 服务器应使用的证书。  
  
这很好地说明了如何  
https://ixon.cloud与本地安装的 VPN 客户端进行交互，以及我们将 OpenVPN 作为我们的底层 VPN 软件。  
  
建立连接  
  
因此，单击connectVPN 设备后，  
https://ixon.cloud JavaScript 会从用户浏览器向 Web 服务发送 XHR 请求  
https://localhost:9250：  
  
```
POST/connect HTTP/1.1Host: localhost:9250Api-Access-Token: a[..REDACTED_ACCESS_TOKEN..]bApi-Version: 2Vpn-Client-Controller-Identifier: a[..REDACTED..]bUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36Content-Type: application/jsonOrigin: https://portal.ixon.cloudReferer: https://portal.ixon.cloud/{    "companyId":"a[..REDACTED..]b",    "agentId":"a[..REDACTED..]b"}
```  
  
  
这个请求包含三个重要的条目：  
Api-Access-Token、  
companyId 和  
agentId。这三部分构成了是否允许连接的身份验证和授权。  
  
Api-Access-Token与 中使用的身份验证承载相同， 并且  
https://ixon.cloud指  
agentId的是应建立连接的 IXON VPN 设备。  
  
当本地 Web 服务器收到此请求时，它会将其转发到  
https://ixon.cloud 本地 VPN 客户端并附加其配置详细信息：  
  
```
POST/api/users/me/vpn-configs?fields=agent(publicId,name,activeVpnSession(rscServer.name,vpnAddress),config(routerLan(network,netMask),routerAdditionalSubnets(networkAddress,networkMask))),company(publicId,name) HTTP/2Host: portal.ixon.cloudAuthorization: Bearer a[..REDACTED_ACCESS_TOKEN]bApi-Company: a[.:REDACTED..]Accept: application/jsonApi-Version: 2User-Agent: VPN Client/1.4.2 (Linux x86_64 (Kernel 6.11.2-amd64)){    "type":"openvpn"    "networkLayer":"tap"    "transportProtocol":"tcp"    "agent":{"publicId":"[..REDACTED..]"}    "addRoutes":"true"    "rsaPubKey":"-----BEGIN RSA PUBLIC KEY-----\n[..REDACTED..]\n-----END RSA PUBLIC KEY-----\n"}
```  
  
  
该请求的响应是 OpenVPN 配置（.ovpn），IXON 提供的本地 OpenVPN 二进制文件使用它作为连接。  
  
CVE-2025-ZZZ-01 - [已编辑]  
  
我们已决定在公开修复程序发布之前不会披露此漏洞。IXON 已意识到此问题；然而，修复此漏洞可能需要进行一些可能影响深远的配置更改。该攻击类型较为特殊，虽然 IXON 已接受此漏洞可能被披露，但 Shelltrail 认为，在目前尚未得到适当修复的情况下公开此漏洞是不负责任的。  
  
CVE-2025-ZZZ-02 - IXON VPN 客户端本地权限提升 Linux  
  
好的。现在我们对 IXON VPN 客户端的内部工作原理有了相当深入的了解。如果你还记得的话，当 VPN 连接即将建立时，本地二进制文件会收到一个 OpenVPN 配置。回顾这次交接时，我们注意到 OpenVPN 配置会临时存储在磁盘上。  
  
通过观察文件写入  
vpn_client情况，发现 OpenVPN conf 存储在/tmp目录中，并且名称可预测：  
/tmp/vpn_client_openvpn_configuration.ovpn。渗透测试人员的大脑开始全速运转。  
  
此外，一旦建立 VPN 连接，临时的 OpenVPN conf 就会被删除。  
  
OpenVPN 以能够在连接过程中执行 shell 脚本而闻名（如果用户提供）  
up，  
pre或者  
tls-verify在配置中附带  
script-security级别 2。  
  
```
script−security 2tls−verify /tmp/script.sh[...]
```  
  
  
因此，如果我们成功将  
tls-verify和  
script-security参数偷运到 OpenVPN conf，我们将以 root 身份执行代码。  
  
最初的想法是使用代理功能  
vpn_client来替换传输过程中的 OpenVPN conf，但是由于 TLS 传输中的证书验证，这是不可能的。  
  
第二个想法是预先配置一个 OpenVPN 配置文件，  
/tmp/vpn_client_openvpn_configuration.ovpn 并使其不可更改，chattr +i <file>这样就vpn_client无法覆盖它。这个方法行不通，因为vpn_client如果配置文件没有正确的文件权限，进程就会停滞。  
  
chown所有类型的符号链接和针对文件位置的特技都会出现同样的问题。  
  
几天过去了，这个看似教科书式的权限提升问题仍未得到解决。  
  
直到……我们想到了管道！  
> mkfifo 命令用于在 Linux 中创建命名管道 (FIFO)。FIFO（先进先出）是一种特殊类型的文件，允许进程间通信 (IPC)，其中一个进程将数据写入管道，另一个进程从中读取数据。  
  
  
如果该位置存在预先创建的 FIFO 命名管道  
/tmp/vpn_client_openvpn_configuration.ovpn 并且激活了 VPN 连接，则该连接  
vpn_client将会暂停，直到将 OpenVPN 写入管道。  
  
下图显示了以下步骤：  
1. 打印/tmp/script.sh 的内容  
  
1. 打印正在运行的 OpenVPN 配置的前 4 行  
  
1. 在临时存储的 VPN 配置的已知位置创建 FIFO 命名管道  
  
1. 显示文件 /tmp/root 不存在  
  
1. （现在用户登录portal.ixon.cloud并连接到VPN设备）  
  
1. 二进制文件vpn_client暂停并等待 OpenVPN 配置  
  
1. 恶意的 OpenVPN 配置被写入命名管道，并以 root 身份执行提供的脚本，并将证据打印到名为  
 /tmp/root 的文件中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeE4A70ZJcGMWKhyvy6SjkW5BUcmKeLkpEzafY5Fa0tMlVUmgvJIBovBqIDNibqYVqZ8ZoXO8Up4fg/640?wx_fmt=png&from=appmsg "")  
  
这里需要强调的是，OpenVPN conf 需要成功连接才能  
tls-verify执行脚本。同样的要求也适用于   
up。为了  
down执行 ，首先需要建立连接，然后关闭连接。  
  
运行预连接脚本早在 12 年前就被讨论过，但由于存在安全风险而被拒绝（https://community.openvpn.net/openvpn/ticket/284）。  
  
这项提议之前已经提出过，但由于此方法存在安全问题，我拒绝了它。  
  
如果有人有绕过连接建立警告的想法，请随时给我们留言。  
  
CVE-2025-ZZZ-03 - IXON VPN 客户端本地权限提升 Windows  
  
哦——很高兴你问这个问题。当然有Windows客户端可以看看。  
  
建立 VPN 连接的过程与 Linux 相同。  
  
作为服务运行  
vpn_client的内容如下  
NT Authority\SYSTEM：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeE4A70ZJcGMWKhyvy6SjkWGBP8eGUt7g9DOhSoicqGtgtOXg950sE8Egof9ibmTXZibVSK0l18cf74A/640?wx_fmt=png&from=appmsg "")  
  
当与 IXON VPN 客户端连接时，OpenVPN conf 会临时存储在  
C:\Windows\Temp。啊，就像一位老同事说的那样，%TEMP% 的故事真幸福。  
  
以下是我们关于 %TEMP% 的 5 个有趣事实，您可以在无聊的晚宴上讨论：  
1. NT Authroity\SYSTEM的环境变量 %TEMP% 指的是  
C:\Windows\Temp  
  
1. 标准用户，  
%TEMP% 指向  
C:\Users\<username>\AppData\Local\Temp  
  
1. 标准用户无法列出内容  
C:\Windows\Temp  
  
1. 标准用户可以在  
C:\Windows\Temp  
  
1. 文件或子文件夹的创建者获得完全权限。  
  
因此，我们知道了将在 中创建和删除的文件名。并且，我们可以在服务将 OpenVPN conf 写入该位置之前控制路径。如果能像https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks   
C:\Windows\Temp中描述的那样，通过 Windows 安装程序回滚来使用任意文件删除权限提升技术，那岂不是很酷？  
  
当然这很酷，但是这要求创建符号链接的文件夹为空 - 而这是不可能的  
C:\Windows\Temp。  
  
有时，并非每个想法都必须很复杂......也许while 以低权限用户身份在 Powershell 中进行循环，不断将我们的恶意 OpenVPN conf 复制到可预测的文件位置，将导致竞争条件和脚本的执行。  
  
让我们来找出答案：  
  
巨大的成功。  
  
  
概括  
  
IXON 在漏洞沟通和修复方面反应非常迅速。两次权限提升问题都通过简单地将临时 OpenVPN conf 文件移动到只有高权限用户才能访问的文件夹来解决。  
  
[删除] 尚未修复。  
  
IXON 在https://support.ixon.cloud/s/article/Security-advisories上跟踪了这些漏洞， ID 为 ADV-2025-03-17。  
  
IXON 建议客户升级到 VPN 客户端 1.4.4 或更高版本。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
  
