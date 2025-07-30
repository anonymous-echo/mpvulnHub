#  黑客组织利用ProxyShell漏洞攻击医疗保健提供商   
 关键基础设施安全应急响应中心   2022-04-20 14:33  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmzNjhpz1bJpLPx6QARiaFNueUwmxyg8t1p6t2oSvxxsEjqYwAaTYBUpg/640?wx_fmt=jpeg "")  
  
去年12月初，加拿大的一家医疗服务提供商先后遭到了两个不同黑客组织采用同一攻击策略的攻击。第一个勒索软件组织，被命名为“Karma”，他们窃取了数据，但没有加密目标的系统。  
  
第二个攻击组织被确认为Conti，后来进入网络，但没有留下勒索信。在Karma组织发出勒索信后不到一天，Conti的攻击者们就使用了同一勒索软件发起了攻击。在这几个案例中，勒索软件附属公司利用ProxyShell渗透攻击目标的网络，包括Conti的附属公司，多个攻击者利用相同的漏洞来访问攻击目标。但是，这些案例中很少有同时涉及两个勒索软件组织的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogsfQcwvibHxyNaIXyzoyjA7ZtNXdy1vdLQUwGAzaYe3EwBctCQWf3BuVibyFuROicM7yXia4HTNpwKfiaQ/640?wx_fmt=jpeg "")  
  
这两种攻击者都是通过“ProxyShell”漏洞(针对微软Exchange Server平台上的CVE-2021-34473、CVE-2021-34523和CVE-2021-31207)进入的。根据IIS访问日志的记录，使用该漏洞的第一次攻击发生在2021年8月10日：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmbpicUWXDe3ico1OWnzXjRt8pPriclGCcTSNEKuG9q2oQ6DySM6BGYKrQA/640?wx_fmt=png "")  
  
接下来的命令利用Exchange Management shell创建了一个管理帐户“Administrator”，并从三个远程服务器(一个在香港，另一个在伊朗，最后一个在俄罗斯)检索脚本。  
  
“管理员”帐户稍后将被其中一名攻击者用于横向移动。虽然无法从可用数据中确认，但第一个漏洞很可能是由访问代理设计的，他后来将访问权限卖给了一个(或两个)勒索软件运营商。  
  
第二个攻击组织使用ProxyShell攻击链的攻击发生在11月11日。此攻击在Exchange Server的IIS web服务器实例上安装了web shell。  
  
真正深入渗透网络的努力在几周后正式开始。在11月29日到30日之间，系统日志显示超过20次失败的尝试和尝试连接到其他服务器(包括域控制器)，以及通过帐户“Administrator”从邮件服务器成功连接到另一个web应用服务器。在11月30日的某个时刻，Administrator帐户被用来访问虚拟机或工作站上的RDP会话，这是用来进行登录尝试的。这一活动似乎与Karma组织有关。  
  
与此同时，另一个被攻击的帐户通过一系列远程桌面协议连接到其他服务器，并执行PowerShell命令，从11月30日用于脚本的同一主机下载Cobalt Strike信标。  
  
11 月 30 日，在其他系统上进行了几次尝试后，攻击者使用管理员帐户成功连接到另一个系统 (104[.]168.44.130)，启动了将 Cobalt Strike “信标”安装为服务的批处理脚本。Cobalt Strike 被部署到电子邮件服务器、域控制器和其他一些系统上，第二天又有更多系统成为目标。  
  
收集工作也从12月1日开始，创建了多个系统上的压缩文档。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogsfQcwvibHxyNaIXyzoyjA7ZzH53MufHF2OIoguCXibUPEqHHDR7csFpgaCnP3QeWiaCBI6SBG477mWg/640?wx_fmt=jpeg "")  
  
在12月1日和2日，Karma组织完成了数据收集，并将其提交给Mega云存储服务，造成了 52 GB 的数据泄露。然后Karma恶意软件被部署了，使用的正是被攻击的管理员账号。  
  
恶意软件通过在每个目标系统上创建的服务来传播赎金通知，该服务从原始位置复制赎金通知，并启动一个批处理文件，例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmWXibIkuu1z0OuI5lu7NFa5ibWI0kFeF7go3iaDbTjfP4g1kKdcvnrLnEA/640?wx_fmt=png "")  
  
12月3日开始工作时，该组织的员工发现，“Karma”赎金通知作为壁纸出现在大约20个工作站和服务器上。这封勒索信声称，数据只是被外泄，没有加密，因为 Karma 团伙已将目标确定为医疗机构。  
  
被攻击的组织通过监测发现，在攻击开始后的几个小时内，第二个勒索软件组织发起了攻击。  
  
12 月 3 日，两个被盗帐户处于活动状态——管理员帐户和具有管理权限的第二个帐户。其中一个帐户在主文件服务器上安装了 Chrome 浏览器。  
  
然后，通过被攻击的管理员帐户，恶意软件被部署到该组织的一个服务器上。示例64.dll被sophoslab识别为Conti。它是使用regsvr.exe加载的。在执行过程中，会启动一个批处理文件def.bat，其中包含在目标服务器上禁用Windows Defender的命令。  
  
这发生在Karma向其他系统发送勒索信的时候。与此同时，目标组织的网络防御系统检测并阻止了来自该组织的一个邮件服务器(而不是作为入口的服务器)的Cobalt Strike活动。检测到的 Cobalt Strike C2 通信是发往由保加利亚托管公司运营的荷兰数据中心的服务器。第二个被攻击的帐户用于将 Cobalt Strike 信标下载到网络上的其他系统。  
  
不久之后，第二个被盗的帐户被用来将一个脚本放入域服务器的本地文件夹，名为 Get-DataInfo.ps1 的 PowerShell 脚本通过 Windows Management Instrumentation 查询收集网络数据并将其发送回远程命令和控制服务器。部分脚本已从系统日志中恢复，它在网络上的计算机上搜索感兴趣的软件，包括反恶意软件和备份软件，以及其他可能干扰勒索软件加密的软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmFg12lFeUa0eJPByWt4TCyvdfJejxGbWhzhMZ5avgXCZ6q9qx2XiaCMA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufm2TVdgkZgvVqnXHh051I8PJOgElg9gd2iaEIEv9wNpNkHyZHgQoxqoYg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmwqAXcMNdOsgVX81ZqC3mrvVAUSej1VQw4AGibbmOG9bhHNMCiasPCfBg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icQdxq7ekQQqPgjZPyf3ufmjqohcHTpZYYoeYvTGnxLK6Xpar0uHlsP6mFRibKsgOCvk0cGuC5jHPg/640?wx_fmt=png "")  
  
该脚本曾参与过与 Bazar 后门和 Ryuk 勒索软件相关的活动  
  
12 月 3 日晚些时候，更多数据（价值 10.7 GB）通过当天早些时候放在文件服务器上的 Chrome 浏览器被泄露到 Mega；这似乎是 Conti 集团的外逃。不久之后，Conti勒索软件攻击正式开始，部署了def.bat文件来抑制Windows Defender的检测。勒索软件加密了受影响系统的C：盘上的文件，并发出Conti的勒索信。  
  
 总结  
  
这些双重勒索攻击突出了与众所周知的面向 Internet 的软件漏洞相关的风险——至少，那些为攻击者所熟知但可能不为运行受影响软件的组织所熟知的风险。各种规模的组织都可能在漏洞管理方面落后，这就是为什么拥有针对恶意活动的多层防御非常重要的原因。服务器和客户端的恶意软件保护可以阻止勒索软件运营商使用未受保护的服务器发起攻击。  
  
**参考及来源：**  
  
https://news.sophos.com/en-us/2022/02/28/conti-and-karma-actors-attack-healthcare-provider-at-same-time-through-proxyshell-exploits/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg "")  
