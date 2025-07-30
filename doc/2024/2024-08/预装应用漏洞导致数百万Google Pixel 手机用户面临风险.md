#  预装应用漏洞导致数百万Google Pixel 手机用户面临风险   
flyme  独眼情报   2024-08-17 14:18  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQsTib8mC7oxR9whnpGydUiamIoFib4VmQhV5M4JyeedKicd9OUoyStcaxiaHyeLfFqjsxPZZRd6eTrR2Q/640?wx_fmt=other&from=appmsg "")  
  
iVerify 的网络安全研究人员与 Palantir Technologies 和 Trail of Bits 合作，发现全球数百万台 Google Pixel 设备存在严重漏洞。该漏洞源自预装的“Showcase.apk”应用程序包，存在严重的安全风险，允许网络犯罪分子执行远程代码、安装恶意包并对受影响的设备进行中间人 (MITM) 攻击。  
  
  
  
该漏洞自 2017 年 9 月起出现在 Google Pixel 设备中，源于 Showcase.apk 应用程序被授予过多的系统权限。该应用程序最初旨在将 Pixel 设备转换为零售环境的演示单元，但攻击者可以操纵该应用程序在系统级别执行代码，从而有效地将设备变成黑客的游乐场。  
  
  
此漏洞最令人担忧的方面之一是应用程序检索其配置文件的方法。该应用程序通过不安全的 HTTP 连接与单个位于美国的 AWS 托管域进行通信。由于缺乏安全通信，配置文件容易受到拦截和操纵，可能允许恶意行为者将有害代码直接注入设备的操作系统。  
  
Showcase.apk 漏洞尤其危险，因为它有可能引发 MITM 攻击。通过利用不安全的 HTTP 连接，网络犯罪分子可以拦截和更改配置文件，从而能够在受感染的设备上执行系统级命令。这可能导致安装危险的间谍软件、未经授权访问个人数据以及完全接管设备，从而导致进一步的网络犯罪和数据泄露。  
  
  
  
更糟糕的是，该应用程序深深嵌入在 Pixel 固件中，无法通过标准卸载方法将其删除。尽管默认情况下该应用程序处于非活动状态，但可以通过各种方法启用该应用程序，这引发了人们对它可能在未经用户同意的情况下被激活的担忧。  
  
Showcase.apk 由 Smith Micro 公司开发，该公司以提供远程访问和家长控制软件解决方案而闻名，其目的可能是提高 Verizon 商店中 Pixel 设备的销量。然而，它被纳入全球数百万台设备的固件中，无意中将无数用户置于风险之中。  
  
该应用程序的设计缺陷众多且令人担忧。它无法验证或验证其从中检索配置文件的域，在证书和签名验证期间使用不安全的默认设置，并通过可预测构造的 HTTP URL 进行通信。这些弱点为网络犯罪分子创造了多种攻击媒介，他们可以利用该应用程序的特权访问权限来破坏设备。  
  
  
尽管收到 iVerify 的通知，谷歌仍未发布补丁或从受影响的设备中删除存在漏洞的软件，导致数百万用户受到影响。  
  
  
  
每台 Pixel 设备上预装了具有如此广泛权限的第三方应用程序，这引发了人们对质量保证以及第三方应用程序在设备固件中的作用的质疑。  
  
为了应对这一漏洞，发现该漏洞的关键参与者 Palantir Technologies 已宣布计划逐步淘汰其移动设备中的 Android 设备，并选择在未来几年内完全过渡到 Apple 设备。  
  
有关此漏洞的完整详细报告，包括技术分析和渗透测试结果，可从  
iVerify 网站  
下载。但是需要企业邮箱。  
  
> iVerify 网站：https://iverify.io/resources/showcase  
  
iverify 的报道：https://iverify.io/blog/iverify-discovers-android-vulnerability-impacting-millions-of-pixel-devices-around-the-world  
  
  
  
  
  
  
  
