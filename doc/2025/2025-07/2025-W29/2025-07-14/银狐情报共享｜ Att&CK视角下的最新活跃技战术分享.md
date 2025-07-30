> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247527649&idx=2&sn=417589fe6d2e592069355e13173139fe

#  银狐情报共享｜ Att&CK视角下的最新活跃技战术分享  
 腾讯安全   2025-07-14 09:20  
  
**前言**  
  
  
近年来，银狐针对国内企业数据资产及个人终端的定向攻击频发。通过进行敏感信息窃取，控制系统操作聊天应用以社工工程学为核心开展金融诈骗活动，已成为当前严重威胁企业/个人安全的攻击团伙之一。  
  
  
腾讯安全作为国内兼具云管端安全产品与威胁情报能力的综合性安全厂商，同时深度协同腾讯生态产品打击银狐钓鱼攻击，具备核心威胁感知优势。目前腾讯安全在银狐基础IOC检测、行为TTPs防护、驻留项和防御规避技术检测及清理等方面积累大量独家方案，经个人与企业客户场景充分验证有效。为联合更多安全厂商和企业安全部门打击银狐钓鱼攻击，我们将持续分享银狐团伙的最新情报和攻防技术方案，共同护航产业互联网安全。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelQgs5yApEmNLcFibpwicL1YzoVQrtpJ2RpOlticKy5wDCibYQFlVnWYk8THHOs60HWlKickQB0p5aV9qA/640?wx_fmt=png&from=appmsg "")  
  
  
本文我们将通过公开近期银狐攻击过程中活跃技战术TTPs（战术、技术、步骤），总结特点供业界参考。  
  
  
银狐攻击过程技战术使用丰富（attck矩阵黄色标记），本文我们着重对其活跃使用且对抗激烈的技战术（attck矩阵红色）其进行总结。其中某技战术手法首次对外披露（使用文件关联+设备映射+PendingFileRenameOperations机制实现绕过安全软件无痕启动）。同时，我们也发现银狐开始结合Rootkit来进一步做更深层的系统潜伏和对抗检测，我们将在之后系列文章中再次同业界分享。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdelQgs5yApEmNLcFibpwicL1YzKIuftSxr2ZiajhhQP3F4zalg0tIialjiaLS7tIAYYlXyibUHemMmcfEDlA/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
银狐特性总结  
  
  
  
传播方式多样  
  
  
以钓鱼攻击、水坑攻击、第三方软件捆绑传播为主。通过社交工程邮件、即时通讯工具充分利用社会工程学、时事热点（*名单、*吃瓜、*税务、*票据等）投递恶意文件。通过仿冒合法网站（有道、酷狗、向日葵、Telegram、Google、DeepSeek等）植入恶意软件，定向诱导工具需求人群下载。  
  
  
攻击目标精准  
  
  
针对财务、税务、人事、运维等企业关键核心人员展开定向攻击，窃取核心机密权限，长期控制主机伺机开展金融诈骗活动。  
  
  
技术手段复杂  
  
- 白利用：使用合法带数字签名的程序进行白利用（传统DLL劫持、.net appdomain劫持、trueupdate解释工具等），加载执行恶意模块代码；或直接将具备远控功能的软件C2武器化。  
  
- 内存注入：将恶意代码通过各类技术手段（远线程、Apc、Context、PoolParty等）注入合法进程（explorer.exe、lsass.exe、wusa.exe、tracerpt.exe、regsvr32.exe、dllhost.exe等）的内存空间中运行，隐藏自身恶意代码。  
  
- 载荷隐写：将恶意代码隐藏于非可执行文件（如图文、视频、文档）或注册表中，通过特定解析逻辑提取并执行。  
  
- 安全对抗激烈：通过技术手段（BYOVD、系统防火墙、网络策略、WDAC策略、安全软件VT兼容考虑、安全软件进程打开权限管控兼容考虑）关闭或干扰安全防护软件正常运行，修改系统配置使其无法检测恶意行为。  
  
- 持久化创新：除通过启动目录、注册表Run、服务、计划任务等方式持久化外，还通过UserInitMprLogonScript跟随系统启动。同时为了进一步绕过安全软件检测，创新式将启动目录进行劫持，使用文件关联+虚拟设备映射+PendingFileRenameOperations机制实现绕过安全软件无痕启动，极具创新性。  
  
版本迭代快速  
  
  
通过样本增肥躲避云查杀，绕过部分安全软件快速检测机制。每日生成大量新变种，通过注册大量云设施，频繁更新C2信息以躲避安全厂商围剿。  
  
02  
  
初始访问  
  
（Initial Access：TA0001）  
  
  
  
水坑攻击（Drive-by Compromise：T1189）  
  
  
银狐主要使用MSI、EXE两种类型伪装常见的安装包应用，通过仿冒工具站SEO后，诱导受害者下载执行。常见伪类应用包括PDF工具、WPS、酷狗、向日葵、浏览器、飞书等。同时银狐也通过仿冒特定应用人群使用应用（虚拟币、TG、VPN等软件）进行精准投放，用于定向窃取虚拟币等资产。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh01BkMKotDhsW0ztJu5FO3FZc2icLypsMjOww5AoxaEGOMI7vtjuVsfvQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0Kd7gJJPmR4cdcynX8r9elq71rhZEoaJ9iamE4OcQkSSdCXMKFNxOhiaw/640?wx_fmt=png&from=appmsg "")  
  
  
钓鱼攻击 （Phishing：T1566）  
  
  
银狐擅长使用热点类新闻开展钓鱼，通过具有诱惑性（吃瓜、税务、薪酬、票据等）的钓鱼正文内容，诱导被害者下载点击（msi、exe、chm、vbs、bat）等恶意附件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh09OGGo8U8LqibCWtuJvtiaV768OB7Nj0ujEEpDhP2G4mYx1D6QdHJnHPw/640?wx_fmt=png&from=appmsg "")  
  
  
03  
  
诱导执行  
  
（Execution：TA0002）  
  
  
  
用户执行（User Execution：T1204）  
  
  
整理银狐常见类伪装恶意载荷名如下。一旦受害者主动点击恶意附件，银狐后门则会在系统内开展进一步隐蔽对抗，持久化驻留。随后银狐攻击团伙对被害者主机展开持久控制，伺机实施金融窃密/诈骗过程。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0jxXf4l1Uc4E3ibABA3uia7clyy3ywlH4h8myicDtGX3x3zMdv7uHFPhkg/640?wx_fmt=png&from=appmsg "")  
  
  
历史情报：暗流涌动：钓鱼木马再来袭  
  
04  
  
防御规避  
  
（Defense Evasion：TA0005）  
  
  
  
白利用  
  
  
传统软件DLL劫持白利用（Hijack Execution Flow：T1574）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
Windows系统加载程序时，需要调用动态链接库DLL（相当于程序的“工具包”）。但系统有个“弱点”，加载DLL时，会按固定顺序搜索目录，优先从程序自己的文件夹找（比如你安装的QQ目录），找不到再去系统目录（比如C:\Windows\System32）。  
  
  
攻击者就钻这个空子：伪造一个和系统DLL同名/或应用程序自身需要的“假DLL”（比如lpk.dll、ws2_32.dll），放到程序的文件夹里。当程序运行时，系统会先加载这个“假DLL”，而“假DLL”里藏着木马的代码——程序以为自己在用系统工具，实际上被木马控制了。  
  
  
例如下图利用迅雷白模块，通过合法签名软件DLL劫持，执行最终恶意载荷。装载同目录XLFSO.dll，XLFSO.dll进一步装载mt.dll，最终装载同目录内非PE文件mi.jpg。查看mi.jpg可知文件头为一段shellcode，进一步执行其内部Embedded PE后门。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0IiamIbp3nTSZpea58YgPic5LiaMMQicicXXKXfEIDaNPnib8aEN9KLgT2fZg/640?wx_fmt=png&from=appmsg "")  
  
主程序具有合法签名  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh02usU0WBGIJdpgq39XgnvjTwA2SxSN6zsFHlMUBBGSicQBXtKHKuAHmA/640?wx_fmt=png&from=appmsg "")  
  
经过DLL双层劫持后装载外部非PE图片mi.jpg文件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0rcJQ5mE9FiaV5dWqJA8ria5qOicic6WUYjFS6OkBPtbE8TnPSKdibdMwWLQ/640?wx_fmt=png&from=appmsg "")  
  
mi.jpg图片文件本质为shellcode装载器+Embedded PE的恶意后门  
  
  
后门最终外联C2地址：12-18.qq-weixin.org。通过该域名不难看出，银狐为了躲避安全厂商围剿，进一步隐蔽其c2通信过程，使用到的恶意c2资产仿冒了国内知名软件域名。正常情况下，普通人很难发现该域名下的异常流量通信行为。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0XDYnOzCmuXNWJf7icrMbP5icLnbicecT9Ribibdice5TabJopbqmYtuz8WWA/640?wx_fmt=png&from=appmsg "")  
  
  
NET白文件AppDomainManager劫持（Hijack Execution Flow：T1574）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
.NET程序运行时，会通过AppDomainManager（应用程序域管理器）来创建和管理“应用程序域”（隔离代码执行的沙盒）。攻击者通过篡改这个“管理者”，可以让它在创建域时执行恶意逻辑。攻击者可通过修改.NET程序的配置文件或环境变量，让程序加载自定义的AppDomainManager程序集（负责管理.NET应用程序域），从而在程序启动时执行恶意代码。  
  
  
如下案例，银狐利用Microsoft WSE（UevAppMonitor.exe）的白程序，配置其程序同目录下同模块名的config文件，配置中appDomainManagerAssembley字段。  
  
  
当该程序执行时，WSE程序进一步尝试加载目录下配置的ureboot.Commands.exe程序集，ureboot.Commands.exe恶意程序集模块最终使用0xEE进行动态解密外部n180yhty.mdb文件，对其进行装载后，执行后门远控外联C2；同时恶意代码还具备恶意代码注入系统进程内实现进程守护的功能。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0T5D14ERUiaScPaHTg0zx80dCp57qCQ0XOQBdL8ONcsCDMzW9MuB4W6Q/640?wx_fmt=png&from=appmsg "")  
  
攻击者篡改后的appDomainManager劫持信息，白利用文件为Microsoft WSE白程序  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh04yuUPlkzfAFq1hgLiaa84b4bkLDBD6ghdrK8zsw6BjKJiatpvMUyxWjg/640?wx_fmt=png&from=appmsg "")  
  
ureboot.Commands.exe程序集使用0xEE作为key解密恶意代码后进行二阶段恶意载荷装载  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0z8P9cX43OATr51ahNCicevsRia1O6UO2CVKHYW4FQGOib4ia16V40FSvYA/640?wx_fmt=png&from=appmsg "")  
  
同时最终后门通过将核心注入系统白进程（tracerpt.exe）实现进一步隐蔽自身目的  
  
  
最终外联C2：156.152.19.180，该资产来自境外，使用该类型资产可进一步增加其团队溯源难度。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0IK2eAbMWJicLchW2D8xmGCIyQdaLkuBd01icI2vTVdLyiaHbkibxVJEFqA/640?wx_fmt=png&from=appmsg "")  
  
  
TrueUpdate白利用（System Binary Proxy Execution：T1218）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
TrueUpdate是IndigoRose公司开发的打包安装工具，支持通过Lua脚本自定义安装逻辑（如文件释放、注册表修改、网络请求等）。木马（如“银狐木马”）利用其打包隐蔽性、脚本自定义能力及密码保护机制，实现对系统的隐蔽渗透与持久控制。  
  
  
如下图，银狐木马利用TrueUpdate加载外部lua脚本dat文件，进一步装载外部jpg，xml非PE中的恶意后门载荷。由于整个恶意代码加载过程涉及白文件+非PE文件。检测能力弱的安全软件将无法检测到过程中的恶意代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0M0iaLCB2Lh8LJhDVrnoUcbHf5nM7Hkjr1s6fticpxZ26DxJZ3UF39PEg/640?wx_fmt=png&from=appmsg "")  
  
  
合法软件白利用武器化（Remote Access Tools：T1219）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
合法远程软件（比如TeamViewer/edr或上网管理类软件）本身有强大的远程控制功能：能跨网络连接、传输文件、甚至控制键盘鼠标。木马直接自己写一套远程控制功能很麻烦，不如“偷懒”——直接利用现成的合法软件，既能绕过系统限制（比如防火墙可能默认允许这些软件联网），又能伪装成正常操作（用户看到是熟悉的软件界面，不容易怀疑）。  
  
  
简单说，就是木马把原本用来远程控制的合法软件改造成“木马工具”，让它变成黑客的“遥控器”，偷偷控制别人的电脑。  
  
  
使用IPGUARD（历史情报：情报速递20240516｜“银狐”钓鱼团伙利用某安全软件管控功能进行攻击），固信管理。由于该系列软件具备合法的远程控制功能，且具备驱动级权限，银狐团伙积极将其武器化使用。  
  
  
如下图所示，伪装税务app的程序运行后，会安装名为pobus64的某终端EDR管控产品，由于该软件具备远程管理功能，攻击者将其武器化做C2工具使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0Xd8wh13z4b9Gj1BbF9OWoficm2hicXarhErReVibbBjsD0tbX6vyZKoJw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0xdoGicSzsFJaYoFYWJQRicwyN2cbDE31lticyXpM6hlBIce9sOjH4eM9w/640?wx_fmt=png&from=appmsg "")  
  
  
安全对抗  
  
  
银狐执行时，为了实现在安全软件监控下持续运行，会尝试使用多种方式对抗安全软件。包括断网/防火墙策略部署绕过安全软件云策略监控；安装VT功能软件利用兼容性绕安全软件主动防御；利用安全软件兼容考虑注入LSASS进程对抗安全进程；通过BYOVD利用获取内核权限深度对抗；利用WDAC策略禁用安全软件等。目标直接结束掉安全软件或者屏蔽掉安全软件的部分能力，达到长期控制主机下不被查杀。  
  
  
BYOVD（Exploitation for Privilege Escalation：T1068）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
BYOVD（Bring Your Own Vulnerable Driver，自带漏洞驱动）是一种内核级攻击技术，核心逻辑是：攻击者利用系统中已存在的、带漏洞的合法驱动程序（比如系统自带或知名软件附带的驱动），通过漏洞获取内核权限，绕过用户态安全软件的防御，直接在内核层面执行恶意操作（如关闭杀毒软件、窃取数据）。  
  
  
一些公开热门的BYOVD开源利用项目：  
  
https://github.com/BlackSnufkin/BYOVD  
  
https://github.com/ZeroMemoryEx/Blackout https://github.com/Helixo32/NimBlackout https://github.com/Hagrid29/BYOVDKit https://github.com/BlackSnufkin/GhostDriver  
  
  
如下图银狐在系统内安装存在漏洞的wsftprm.sys的白驱动程序，由于该内核文件存在漏洞，加载后可通过在应用层发送相关IOCTL实现结束任意受内核程序保护的软件（例如安全软件）进程。银狐团伙将此类型内核模块插件化使用，可有效获取内核权限，将对抗战场进一步从应用层牵引到了内核态。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0ia15UiavnKvmZYiaqtvzoibKXZyCP63icl3ZwB7ficBKiaynfvibngJsXyeG6Q/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh05WYMicDVpG5uu8zet7XF0lF6qERPoVBOlnGr07Z7IQV4DYx2ibgIDtdA/640?wx_fmt=png&from=appmsg "")  
  
  
网络策略对抗（Impair Defenses：T1562）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
木马的核心目标是长期潜伏、不被发现、完成黑客任务。断开/限制网络能减少“被追踪”和“被拦截”的风险；限制安全软件流量则让防御工具“变瞎变哑”，无法有效反击。两者结合，木马就能更隐蔽地控制电脑，实现窃取数据、破坏系统等目的。  
  
  
如下图银狐使用netsh设置错误的本地IP连接静态地址策略，从而导致网络暂时中断，实现屏蔽安全软件云端检测/防护策略执行后续恶意行为。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh05O5kWzGwsuTticyPfSllEPhEukWyoZhCu9bqK2PtciaChutNhuy81Zicg/640?wx_fmt=png&from=appmsg "")  
  
  
WDAC策略滥用（Impair Defenses：T1562）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
WDAC（Windows Defender Application Control，Windows Defender应用程序控制）是微软推出的一项系统安全功能，核心作用是控制哪些程序能在电脑上运行。它通过“白名单”机制，只允许明确受信任的程序（如系统自带工具、企业认证软件）执行，阻止未知或恶意软件运行，常用于企业环境保障系统安全。  
  
  
木马利用WDAC策略对抗安全软件，本质是“借刀杀人”——用系统自带的安全功能，反过来限制安全软件的运行。它通过篡改“允许运行的程序清单”，让安全软件成为“被禁止的对象”，而木马自己则被加入“白名单”，从而实现长期潜伏、不受监控的攻击目标。  
  
  
如下图，银狐木马释放名为SIPolicy.p7b的WDAC策略配置bin文件。对其进行解码后查看其内容可知，其中配置了安全软件相关进程/模块/目录下的拒绝策略，攻击者意图使用系统WDAC策略禁止安全软件启动，从而躲避查杀。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0LIib8Gicxic5XOiaicicvia5K8XALmLyXr8icl4Qe3Hiang8OLf2U5sbbuQKqdw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0JxKrZHI6Kic1YvMCuXETnS0paZkqqkiaZV95icqX1ttVibNOtQafia0bibjw/640?wx_fmt=png&from=appmsg "")  
  
  
Windows Defender策略滥用（Impair Defenses：T1562）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
Windows Defender会定期扫描系统文件，如果发现病毒（恶意程序），会隔离或删除它。病毒为了存活，必须让Defender“跳过”自己的位置——这就需要用到PowerShell的Add-MpPreference -ExclusionPath命令（或类似的Set-MpPreference命令）。这个命令的作用是：告诉Defender“这个路径里的文件不用扫描”。  
  
  
如下图，银狐使用powershell.exe Set-MpPreference -ExclusionPath "C:\", "D:\", "E:\", ..., "Z:\"将所有目录添加到排除目录，进而在Windows Defender扫描时对其自身恶意文件模块进行白名单放行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0S5n0FHibIoHCHtbljPWx7nPDyibias3FmEmYpibPVHwEcJ8jODMyNAicYtg/640?wx_fmt=png&from=appmsg "")  
  
  
VT程序滥用（Impair Defenses：T1562）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
Intel VT（Intel Virtualization Technology）是CPU级硬件辅助虚拟化技术，ntel VT通过VMX模式隔离、VMCS控制、EPT内存虚拟化等核心技术，为终端安全软件提供了硬件级的安全隔离与性能保障。其核心优势在于其全维度监控：覆盖API调用、进程行为、内存操作等多个层面。  
  
  
部分安全软件使用VT（Intel Virtualization Technology，英特尔虚拟化技术）实现更底层的系统安全行为监控。该功能属于CPU级别的硬件辅助虚拟化技术，比操作系统内核态Ring 0更底层，属于Ring -1层，兼容性问题更加复杂。银狐充分挖掘安全软件兼容考虑下的临时退出场景。如下图，银狐利用WEGAME反作弊系统使用VT虚拟化时，部分安全软件对WEGAME兼容考虑下的退出场景，从而绕过其主动防御策略。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0Nib1UhHnBQrICo1ZNzx9USpHmglg6HiavWFvvMObbG8icek7jmP2icpApw/640?wx_fmt=png&from=appmsg "")  
  
  
增肥/混淆（Obfuscated Files or Information：T1027）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
木马要绕过安全软件的“围追堵截”，除了隐藏自身代码、伪装成正常文件，还会用“体积增肥”的手段——把自己的文件体积变得异常大（比如从几KB涨到几百MB），让安全软件“看不上”或“认不出”，从而顺利进入电脑潜伏。  
  
  
银狐木马母体可达上百MB，同时也会将一些关键的恶意模块进行单独的增肥，意图使用该方式来规避安全软件云查杀，躲避部分安全软件快速查杀策略。同时，银狐也使用各种代码加壳，混淆手法进一步隐藏特征。  
  
  
历史情报：情报速递20240509｜银狐钓鱼团伙2024年1-5月攻击趋势  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0ibBiaYzuv7wKtbrj72t1EAW2UqmsbHREPlxCKTXvwsBsKCfqAOpUeYHA/640?wx_fmt=png&from=appmsg "")  
  
  
注册表/图片隐写（Obfuscated Files or Information：T1027 ）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
隐写术是木马的“隐形外套”，它将恶意代码（如木马程序、控制指令）隐藏在注册表内，或图片文件（如PNG、JPG）的“像素缝隙”或“文件结构”中，让安全软件误以为这是“正常图片”，从而跳过扫描。  
  
  
如下图，银狐将恶意C2载荷填充到注册表特定位置，使用外部Loader在启动时将其从注册表内读取后进一步装载，使用该方式可有效避免安全软件对其核心恶意功能代码的检测。  
  
  
历史情报：情报速递20240524｜银狐团伙使用核酸检测退费发票信息主题的钓鱼攻击增多  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh07pR5iaJInHAXLvAG1icicnqKNGPYlYZCFffsWHdbuGk4qsUFgibr9XYQ7g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0TfL8KbBUa2gSynR0e1iawoSRmibRgaZMAShT3RGrp5qKJle1pOonicVsw/640?wx_fmt=png&from=appmsg "")  
  
  
05  
  
持久化（TA0003）  
  
  
  
自启动位置（Scheduled Task/Job：T1053，Modify Registry：T1112，Create or Modify System Process：T1543）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
服务（Services）：随系统启动的“隐形守护者”  
  
  
启动目录（Startup Folder）：用户登录的“自动触发器”  
  
  
注册表启动项（Registry Run Keys）：系统级的“隐身开关”  
  
  
计划任务（Scheduled Tasks）：定时/事件的“精准开关”  
  
  
这四种方式均为Windows合法功能，木马通过“伪装”成正常组件（如服务、启动程序、定时任务、注册表配置），绕过用户和安全软件的常规检测。更关键的是，多重机制叠加（如服务+注册表+计划任务）形成“复活链”——即使其中一个被清除，其他机制仍能重新激活木马，实现“野火烧不尽”的持久化控制。  
  
  
银狐持久化形式多样，充分利用注册表、服务、启动目录、计划任务等。除此外，也看到对于计划任务等启动路径上，银狐也常使用一些字符凭借/混淆手法，意图躲避一些终端查杀匹配策略。总结银狐主要使用以下几种方式来混淆路径，干扰查杀。  
  
- 引号包围单个字符检测(如"c"h"r"m"s"t"p")；  
  
- 引号包围路径分隔符检测(如"\"r")；  
  
- 空格引号干扰路径解析检测。  
  
如下图文件名使用引号进行拼接：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0KVMUbZ9sDmWWr2e9tYSTHcNBf8dicV7EHG4fibmUgRoibaib5wCKf6VAPw/640?wx_fmt=png&from=appmsg "")  
  
  
可排查以下相关位置确认是否存在异常启动项：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0ueXFpw4w48XMJN1CoZSUfIWRaEuZaTqWu2JZL2ROIQcyEJD1xibhL5w/640?wx_fmt=png&from=appmsg "")  
  
  
UserInitMprLogonScript（Boot or Logon Initialization Scripts： T1037.001）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
UserInitMprLogonScript 是 Windows 注册表中的一个用户级键值（路径：HKEY_CURRENT_USER\Environment），它的作用是：当用户登录系统时，自动执行该键对应的程序或脚本。  
  
  
 简单说，它就像一个“登录触发器”——你每次输入密码登录电脑，系统都会检查这个键，如果里面有路径，就会自动运行里面的程序。  
  
  
如下图，银狐写入UserInitMprLogonScript内恶意载荷实现持久化执行：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh00UJjqPzsprmxxGDeHOiaRTiaLqkD0fK5FTetP3nk84jJYU3ueGGsvtgQ/640?wx_fmt=png&from=appmsg "")  
  
  
篡改启动目录（Boot or Logon Autostart Execution ： T1547）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
攻击者通过篡改系统内注册表Shell Folders\Startup的根本目的，是让系统“误以为”恶意文件夹是合法的启动目录。系统启动时，会按照注册表的指示，去恶意文件夹里找程序运行，而不会怀疑这个文件夹的“真实性”。  
  
  
这种劫持方式的隐蔽性和危害性都很强，因为它利用了Windows系统的“信任机制”，绕过了安全软件的常规检测。  
  
  
如下图，攻击者劫持启动目录到恶意银狐载荷位置内实现隐蔽执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0x7Rz1G5olagPw1BX73Qz8EGkFAvEwpbzbu5U8tSueI62vIfnoAibc6g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0ianKJZ34b4nvRfIQibhpuGmRTW1WOvCGvkbKXmW65E4OqiamBGicHjCdug/640?wx_fmt=png&from=appmsg "")  
  
  
文件关联+虚拟设备映射+PendingFileRenameOperations机制无痕启动（Event Triggered Execution：T1546，Modify Registry：T1112 ，Boot or Logon Autostart Execution：T1547）  
  
  
**腾讯混元大模型技术点解释：**  
  
  
Windows文件关联：  
  
  
Windows中注册表HKEY_CLASSES_ROOT\[文件扩展名]\shell\open\command很关键，系统用注册表路径来记录“文件类型→程序”的对应关系，用于在打开指定类型文件时，调用对应的程序。  
  
  
Windows新增磁盘设备：  
  
  
Windows中注册表DosDevices项是Windows系统的“盘符字典”，记录了“盘符名字”和“存储路径”的对应关系。通过修改这个字典里的“名字”（比如把F:改成G:），系统就会给对应的存储设备分配新的盘符，实现“新增盘符”的效果。  
  
  
Windows-PendingFileRenameOperations作用：  
  
  
PendingFileRenameOperations是Windows系统的“文件操作待办清单”，专门记录暂时无法完成的文件重命名/删除任务，等下次开机时自动执行。它的存在解决了“文件被占用时无法操作”的问题。主要包括以下常见场景：  
  
- 软件安装/卸载：安装程序需要删除旧版本文件，但旧文件被系统进程占用，就会写入PendingFileRenameOperations，等重启后删除。  
  
- 系统更新：Windows更新时需要替换系统文件，但文件正在被使用，就会记录到PendingFileRenameOperations，重启后完成替换。  
  
- 临时文件清理：系统或程序生成的临时文件，需要删除但被占用，也会通过PendingFileRenameOperations延迟处理。  
  
Windows-PendingFileRenameOperations操作时机：  
  
  
PendingFileRenameOperations的操作时机早于驱动加载，其执行发生在会话管理器（smss.exe）启动后、驱动加载前，是Windows系统启动流程中前置的文件操作步骤，确保驱动加载时文件系统的完整性。  
  
  
我们首次披露银狐使用的一些独特的持久化手法，通过创建虚拟设备，将StartUp目录上层目录映射到新的设备盘位置，同时充分结合文件关联以及PendingFileRenameOperations机制实现隐蔽无痕启动。银狐充分利用相关系统特性，组合实现了一套自创的无痕持久化过程，以实现绕过安全软件监控隐蔽持久化执行，详细过程如下：  
  
  
如下图，银狐写入公共下载目录下一个随机后缀的WOFLD文件+后门exe程序，正常情况下系统重启后木马无法再次执行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0XibWDJ4qK9V3yMhFOp89wX9XtJI4fc8bJJ5jO6ug30LSBTYzzqYPu2A/640?wx_fmt=png&from=appmsg "")  
  
  
银狐创建.wofld随机文件后缀的关联启动，当有.wofld文件执行时，会关联使用后门exe打开。可以看到该位置由于写入的是随机类型后缀的打开关联，并非篡改敏感类EXE、DLL、LNK可执行类程序关联。所以部分安全软件出于用户体验考虑，对该处弱风险行为并不会拦截，此时木马无法实现重启持久化。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0yBMcFxiaZjsb3RicazbxUPjDyhZkm19OD7mIZpQv5bAcWXt8gNnxHhjw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0phUmbz4WwodnPlsFKAu25yUzgXopDN2FZia8vpgwhcl1qjRXCCqAbNw/640?wx_fmt=png&from=appmsg "")  
  
  
银狐创建虚拟设备O盘，将其映射到系统StartUp启动目录的上层，此时木马依旧无法完成持久化启动，由于仅仅是创建了一个Programs目录的映射操作，该动作并不敏感，该弱风险行为安全软件通常会放行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0UcxwSwzOsT5mGZdWOPZ8sv5F9iaYb0S2bxN8S9914fnaAE2nFZLhp2g/640?wx_fmt=png&from=appmsg "")  
  
  
银狐最终利用PendingFileRenameOperations机制，实现在开机启动时将随后wofld类型后缀文件写入O盘下Startup目录内。可以看到，此处写入启动路径位置为O:\Satrtup下，由于该路径并不敏感，所以虽然部分安全软件监控了PendingFileRenameOperations操作，但依旧会对其放行。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0kN4ZATj0ibgWtuvON73gzUKHSRK8icicCRiaDj4NuX7HiapFtmicpDicwApFQ/640?wx_fmt=png&from=appmsg "")  
  
  
由于O盘下Startup此时正好被映射到系统盘启动目录，随机类型文件在开机时被写入启动目录，随机类型文件有机会得到执行。又由于随机后缀文件的打开被关联到下载目录内的木马EXE程序，故系统拉起执行了恶意后门。  
  
  
由于是在开机过程完成的O盘映射目录文件写入，且该操作由Windows会话管理器（smss.exe）完成。该模块启动时间早于安全软件驱动加载。最终绕过了部分终端安全软件严防死守的启动目录监控。同时木马启动成功后，会再次删掉启动目录内已存在的随机后缀启动文件，从而导致整个启动过程在事后完全无感知。  
  
  
分析整个过程，银狐利用系统内3处与启动项无关的弱风险篡改操作，绕过安全软件检测/阻断过程，最终组合实现了一个超级隐蔽，且稳定的无痕持久化方式。  
  
06  
  
影响（TA0040）  
  
  
  
银狐团伙以高度定向性、技术复杂性和社会工程欺骗性为核心，借助其不断演进的对抗性技术组合（安全对抗、内存驻留、持久化创新、 隐蔽性增强、利用合法服务通信）及多维度诱骗策略（如热点时事钓鱼、热门应用伪装），已经构建起“传播-渗透-控制-窃取-诈骗”的完整攻击链路。  
  
  
当银狐木马成功植入系统，攻击者则进一步尝试控制主机。通过远程控制主机桌面，进一步尝试窃密，操作主机开展诈骗等行为，被攻击主机可能出现以下系统异常行为。  
  
- 社交软件大量发送虚假诈骗消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0RRzrvuk4wicpRv07367rgvBlWMaKDjKp7ibib1nekdqKbWnf1tnPqEEKw/640?wx_fmt=png&from=appmsg "")  
  
- 虚拟财产转账过程莫名其妙重定向到黑客账户内。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0IaZqDk6MribVQAr6AYZgyu6UrR6qquoH9nvwZLRR1XpHTvWicAxibVXXw/640?wx_fmt=png&from=appmsg "")  
  
- 系统桌面鼠标莫名自动点击，摄像头自动打开。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh06YVUxvDKUMUsIhia765ia0ay5GGx2T4MpHatGEv4WMaYWTvs2XYAHAUg/640?wx_fmt=png&from=appmsg "")  
  
- 系统内部分系统进程频繁外联可疑地址。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OJbMFMZkdeksbmuCum6nhnfQOJX1icNh0ooyE6yyIL71qHwApKf0CW9GO39G7z0l8TcmicshyF8mELzXKUVSDowA/640?wx_fmt=png&from=appmsg "")  
  
- 系统内工作资料存在打开翻动痕迹。  
  
- 系统内软件/系统账号被频繁异常登录。  
  
- 系统安全（本地防火墙、杀毒软件）防护运行异常。  
  
- 任务管理器中的可疑随机进程CPU占用异常，无法结束。  
  
07  
  
防护建议  
  
  
- 提高警惕，谨防钓鱼攻击：切勿随意打开来历不明的链接、点击接收未知来源的邮件附件或下载安装非可信渠道的应用，对微信群、QQ 群等社交媒体传播的非官方通知和程序保持高度警惕。  
  
- 谨慎处理敏感信息：涉及个人敏感信息输入（如银行卡号、手机验证码等）或钱财转账时，务必谨慎核对信息来源与用途，确保操作安全合法。  
  
- 及时部署安全软件：建议部署终端安全软件，开启钓鱼防护和实时监控功能，并保持系统与安全软件版本及时更新，以具备最新防护能力。  
  
  
  
  
- END -  
  
  
**构建数字安全免疫力，守护企业生命线**  
  
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526481&idx=1&sn=4c3df6a097139dcd269f02605c5288bf&scene=21#wechat_redirect)  
  
**二进制与LLM的碰撞：反混淆技术的新尝试**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526517&idx=1&sn=1d00946ea3bf689b279f9318670cb530&scene=21#wechat_redirect)  
  
**2024漏洞风险启示录：在攻防的螺旋中寻找「治愈」之道**  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247527256&idx=1&sn=5ec2b3e00647bca31d0f43634fa31435&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5OTE4NTczMQ==&mid=2247526425&idx=1&sn=720bc0dc67c58939f2189e19ffb5d9b4&scene=21#wechat_redirect)  
  
**腾讯iOA EDR：全方位狙击银狐木马，破解“钓鱼+免杀”组合拳**  
  
  
  
  
  
