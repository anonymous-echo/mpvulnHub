#  WPS的漏洞原理解析【黑客渗透测试零基础入门必知必会】   
龙哥  龙哥网络安全   2024-09-20 17:59  
  
## 前言  
  
WPS(Wi-Fi Protected Setup，Wi-Fi保护设置)是由  
Wi-Fi联盟推出的全新Wi-Fi安全防护设定标准。该标准推出的主要原因是为了解决长久以来无线网络加密认证设定的步骤过于繁杂之弊病，使用者往往会因为步骤太过麻烦，以致干脆不做任何加密安全设定，因而引发许多安全上的问题。本章将介绍WPS加密模式。  
  
WPS（Wi-Fi Protected Setup）是一种简化无线网络配置的标准。它使用户可以通过按下路由器上的WPS按钮或在设备上输入WPS   
PIN码来轻松连接到无线网络。然而，WPS也存在一些安全风险，因为它可能容易受到恶意攻击。  
### WPS简介  
  
WPS在有些路由器中叫做QSS(如TP-LINK)。它的主要功能就是简化了无线网络设置及无线网络加密等工作。下面将详细介绍WPS。  
### 什么是WPS加密  
  
WPS加密就是使客户端连接WiFi网络时，此连接过程变得非常简单。用户只需按一下无线路由器上的WPS键，或者输入一个PIN码，就能快速的完成无线网络连接，并获得WPA2级加密的无线网络。WPS支持两种模式，分别是个人识别码(PIN，PinInputConfiguration)模式和按钮(PBC，Push Button Configuration)模式。后面将会介绍如何使用这两种模式。  
### WPS工作原理  
  
用户可以将WPS认证产品的配置及安全机制，可以想象成“锁”和“钥匙”。该标准自动使用注册表为即将加入网络的设备分发证书。用户将新设备加入  
WLAN的操作可被当做将钥匙插入锁的过程，即启动配置过程并输入PIN码或按PBC按钮。此时，WPS启动设备与注册表之间的信息交换进程，并由注册表发放授权设备，加入WLAN的网络证书(网络名称及安全密钥)。随后，新设备通过网络在不受入侵者干扰的情况下进行安全的数据通信，这就好像是在锁中转动钥匙。信息及网络证书通过扩展认证协议(EAP)在空中安全交换，该协议是WPA2使用的认证协议之一。此时系统将启动信号交换进程，设备完成相互认证，客户端设备即被连入网络。注册表则通过传输网络名(SSID)及WPA2“预共享密钥(PSK)”启动安全机制。由于网络名称及PSK由系统自动分发，证书交换过程几乎不需用户干预。WLAN安全设置的锁就这样被轻松打开了。  
### WPS的漏洞  
  
WPS的设置虽然给用户带来了很大的方便，但是安全方面存在一定的问题。这是由于PIN码验证机制的弱点导致的网络的不安全。PIN码是有8位十进制数构成，最后一位(第8位)为校验位(可根据前7位算出)。验证时先检测前4位，如果一致则反馈一个信息，所以只需一万次就可完全扫描一遍前4位，pimn时速度最快为2s/pin。当前4位确定后，只需再试1000次可破解出接下来的3位)，校验位可通过前7位算出。这样，即可暴力破解出PIN码。  
### WPS的优点和缺点  
  
通过前面对WPS的详细介绍，可知该功能有优点，也有缺点。  
  
下面将具体介绍该功能的优点和缺点。  
#### 1.优点  
  
WPS能够在网络中为接入点及WPS客户端设备自动配置网络名(SSID)及WPA安全密钥。当连接WPS设备时，用户没有必要去了解SSID和安全密钥等概念。用户的安全密钥不可能被外人破解，因为它是随机产生的。用户不必输入预知的密码段或几长的十六进制字符串:信息及网络证书通过扩展认证协议(EAP)在空中进行安全交换，该协议是WPA2使用的认证协议之一。  
  
WPS支持Windows Vista操作系统。  
#### 2.缺点  
  
WPS不支持设备不依靠AP而直接通信的  
Adhoc网络网络中所有的Wi-Fi设备必须通过WPS认证或与WPS兼容，否则将不能利用WPS简化网络安全配置工作。由于WPS中的十六进制字符串是随机产生的，所以很难在WPS网络中添加一个非WPS的客户端设备WPS是一项新的认证技术，所以并非所有厂商都支持。  
### 设置WPS  
  
如果要进行WPS加密破解，则首先需要确定AP是否支持WPS，并且该AP是否已开启该功能。目前，大部分路由器都支持WPS功能。如果要是有WPS方式连接WiFi网络，则无线网卡也需要支持WPS功能。本节将介绍开启WPS功能及使用WPS方式连接WiFi网络的方法。  
#### 开启WPS功能  
  
在设置WPS之前，首先要确定在AP上已经开启该功能。WPS功能在某些AP上叫做WPS，在某些设备上叫做QSS。下面将以TP-LINK路由器(AP)为例，介绍开启WPS功能的方法。  
#### 在TP-LINK路由器上开启WPS功能。  
  
具体操作步骤如下所述:登录路由器。本例中该路由器的IP地址是192.168.2.1，登录的用户名和密码都是admin。登录成功后，直接找到然后打开就行，现在的都很智能。  
#### 在无线网卡上设置WPS加密  
  
用户要在无线网卡上设置WPS加密，则需要先确定该无线网卡是否支持WPS加密。通常支持802.11 n模式的无线网卡，都支持WPS功能并且在某些USB无线网卡上，直接自带了OSS按钮功能(如TP-LINKTL-WN727N)。本节将介绍如何在无线网卡上设置WPS加密。下面以芯片为3070的USB无线网卡为例，介绍设置WPS加密的方法。不管使用哪种无线网卡设置WPS加密，都需要在当前系统中安装该网卡的驱动，然后才可以进行设置。这里介绍下安装芯片3070的无线网卡驱动。具体操作步骤如下所述。  
  
下载无线网卡3070驱动，其驱动名为RT3070L.exe。开始安装驱动。双击下载好的驱动文件。该界面显示了安装RT3070L.exe驱动文件的许可证协议信息,这里选择“我接受许可证协议中的条款”复选框。然后单击“下一步”按钮。在该界面选择安装类型，这里选择默认的“安装驱动程序与Ralink无线网络设定程序”类型。然后单击“下一步”按钮。此时将开始安装驱动文件，要注意该界面的注意信息。如果当前系统中安装有杀毒软件，该驱动可能安装不完全，建议在安装该驱动文件时先将杀毒软件关闭。然后单击“安装”按钮。从该界面可以看到，该驱动已经安装完成。此时单击“完成”按钮，退出安装程序。这时候将在电脑右下角任务栏会出现一个驱动图标，表明驱动安装成功。  
  
注意:在某些操作系统中，将网卡插入后会自动安装该驱动。如果默认安装的话，同样在任务栏会出现驱动图标。用户可以直接单击该图标进行设置。通过以上的步骤无线网卡的驱动就安装完成了，接下来设置WPS加密方式，使网卡接入到WiFi网络。设置WPS加密可以使用PIN码和按钮两种方法，下面分别介绍这两种方法的使用。  
##### 首先介绍使用PIN码的方法连接到WiFi网络，具体操作步骤如下所述。  
  
双击驱动图标。  
  
在该界面单击第三个图标 （连线设定）。  
  
在该界面单击（新增WPS连线设定）图标。  
  
在该界面显示了WPS的两种连接方式，这里选择PIN连线设定方式，并且选择连接的AP。设置完后，单击（下 一步）按钮。  
  
在该界面选择连线设定模式。该驱动默认支持“登录者”或“受理注册机构”两种模式。当使用“登录者”模式时，可以单击“更新8码”按钮来重新产生一组PIN码;如果使用“受理注册机构”时，会要求输入一组PIN码。这里选择“受理注册机构”，从该界面可以看到有一组PIN码。此时，记住这里产生的PIN码，该PIN码需要在路由器中输入。然后单击(下一步)按钮。  
  
该界面将开始连接WiFi网络。但是，在连接之前需要先将该网卡的PIN码添加到路由器中才可连接。所以，此时在路由器的OSS安全设置界面单击“添加设备”按钮  
  
该界面输入获取到的无线网卡的PIN码。然后单击“连接”按钮  
  
从该界面可以看到，路由器正在连接输入的PIN码的设备。此时，返回界面单击“开始PIN”与AP建立连接。该连接过程大概需要两分钟。  
  
从该界面可以看到，成功连接了网络名称为Test的WiFi网络，并且可以看到连接到AP的详细信息，如验证方法和加密方法等在  
Ralink的启动界面可以看到，主机获取到的P地址、子网掩码、频道及传输速度等。  
  
从该界面可以看到当前主机获取到的详细信息，并且从左侧的图标也可以看到，当前网络为加密状态，无线信号也连接正常。  
  
以上步骤就是使用WPS的PIN码连接WiFi网络的方法。  
##### 接下来，介绍如何使用按钮方式连接到WiFi网络。具体操作步骤如下所述。  
  
驱动图标打开Ralink设置界面  
  
在该界面单击(新增WPS连线设定)图标  
  
在该界面单击(新增WPS连线设定)图标  
  
在该界面选择"PBC连线设定方式"复选框，然后单击(下一步)按钮  
  
在该界面单击“开始PIN"按钮，将开始连接WiFi网络  
  
此时，按路由器上的QSS/RESET按钮  
  
按一下路由器上的QSS/RESET按钮后，返回到Ralink连线设定界面。  
#### 在移动客户端上设置WPS加密  
  
在上一小节介绍了在无线网卡上设置WPS加密的方法。但是，通常人们会使用一些移动设备连接WiFi网络，如手机和平板电脑等。下面将介绍在移动客户端上设置WPS加密的方法。进入高级选项，看客户端的pin，然后进路由器输入客户端的pin就行了。  
### 破解WPS加密（我自己建议wifite）  
  
前面对WPS的概念及设置进行了详细介绍。通过前面的学习可以知道，使用WPS加密存在漏洞。所以，用户可以利用该漏洞实施攻击。在KaliLinux操作系统中，自带可以破解WPS加密的工具。如Reaver、Wifte和Fern WiFiCrcker等。本节将介绍使用这几个工具进行WPS加密破解的方法。  
#### 使用Reaver工具和wash（反正大概率是破解不了，因为路由器前置的wps要求是wpa2级别的）  
  
如果你想看看在你周边哪些AP接入点存在上面这种安全漏洞或潜在地存在这种漏洞最简单的方法就是使用一个绑定了Reaver程序的工具。一款名为Wash的软件可以完成这样的任务，该软件是一个被动式探测软件，可以探测到周边的所有AP接入点，并且显示出该点的 WPS 状态。  
  
wash -i wlan0mon 扫描周围网络是否禁用wps  
  
reaver -i wlan0mon -b f8:1a:67🇩🇪23:5a -vv  
  
Reaver是一个暴力破解WPS加密的工具。该工具通过暴力破解，尝试一系列AP的PIN码。该破解过程将需要一段时间，当正确破解出PIN码值后，还可以恢复WPA/WPS2密码。下面将介绍使用Reaver工具破解WPS加密的方法。在使用Reaver工具之前，首先介绍该工具的语法格式，如下所示。reaver -i -b -vv  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUpM9icw4W4c0uuBMyX29u6qckgJ1Wb7jGgw9K61mqLhzlnsSFAtE78ibQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**网络安全学习包**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkUGiakynth3MRTicLcHaV4MAvjubiaIicUx4ZrMxuSdSicjzT5HfEAzJy782g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkU7VZiaRU6vdoIQC9ToNyrFNvkWmp92gn3R2RWyGVEiaxjTlDjic3dPsW6g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**资料目录**  
1. 成长路线图&学习规划  
  
1. 配套  
视频教程  
  
1. SRC&黑客文籍  
  
1. 护网行动资料  
  
1. 黑客必读书单  
  
1. 面试题合集  
  
  
  
**282G**  
《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
1.成长路线图&学习规划  
  
要学习一门新的技术，作为新手一定要**先学习成长路线图**，**方向不对，努力白费**。  
  
对于从来没有接触过网络安全的同学，我们帮你准备了详细的学习成长路线图&学习规划。可以说是最科学最系统的学习路线，大家跟着这个大的方向学习准没问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/71ibgGpZLr2W93cZWq7t2hVfaCvicInAznWcibcMdSKWsxbRn4qOUH3FiapXR7WicIiaRXx4lp8bNDnKTndzOPmKjERg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/evTLxnBbHv6fa8BCJ5052WLSGZjTIfEDgymVV6FeniaFszgpka15xzMolFmtXDdiaaDJMwXSqTQgRgBicvbYv4tNw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
2.视频教程  
  
很多朋友都不喜欢  
**晦涩的文字**  
，我也为大家准备了视频教程，其中一共有  
**21个章节**  
，每个章节都是  
**当前板块的精华浓缩**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQn8E3Yp6lXhRo3D1Bttpiao3a0poRH29MC1MBC0hk5gKMCiaicy3wOiaUviag/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnHBEMEd0W8dr6zFFQetPOhwiax5u8YYm0YZtWJSmyJ7d85QmuVQEicLVQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
3.SRC&黑客文籍  
  
大家最喜欢也是最关心的  
**SRC技术文籍&黑客技术**也有收录  
  
**SRC技术文籍：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dkY8ctWgyFKc2oWZY3ibCDm5lMpjofvtGCicHTLibsOF8b841UOfozGsdjDvJKiaFgibdTunKlgC9kzrTQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
**黑客资料由于是敏感资源，这里不能直接展示哦！**  
  
  
4.护网行动资料  
  
  
其中关于  
**HW护网行动，也准备了对应的资料，这些内容可相当于比赛的金手指！**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnaPKJSI9dNKiaR4vaJf0hqApKNbJeZnCpsQSElEicDrlAMLkRXHoyKN8A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
5.黑客必读书单  
  
****  
6.面试题合集  
  
  
当你自学到这里，你就要开始  
**思考找工作**  
的事情了，而工作绕不开的就是  
**真题和面试题。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnXxPNhSSySbwUMEWOicYYS62D1UOQExv0cYuVQ68gk2uFF2xJ4TPmRHA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**更多内容为防止和谐，可以扫描获取~**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/NAkrkExZ3dnMVja8hzZpia0AkKu6AWrQnGktIUCicPreibR6b3sx1Qu0CsCZP0sZtCP4RHlMdxXuE4icCFSoL2yyBg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
朋友们需要全套共  
**282G**  
的《**网络安全/黑客技术入门学习大礼包**  
》，可以**扫描下方二维码免费领取**  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7O8nPRxfRT4Zy8efCHagq54hvWttN7A4N5KvFOGmvfiaMJ8yTWJjx3dsmfCPMG5RKqacW5TnZKrPatrickn8pRcw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/TiaI8Dth4IiaRCFva2ZibMZKuNBEDOAEmkULH6MxzBRGa9Fibvuic8pv9cEjY0HWQbamrjGDz4jUgPS7TpprXiagZe6A/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**END**  
  
  
  
  
