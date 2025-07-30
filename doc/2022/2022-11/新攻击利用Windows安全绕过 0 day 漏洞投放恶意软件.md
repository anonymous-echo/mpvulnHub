#  新攻击利用Windows安全绕过 0 day 漏洞投放恶意软件   
 关键基础设施安全应急响应中心   2022-11-29 14:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/iaz5iaQYxGoguq8pgKJiczem4D80NGGW6yAPWzYzql3blm3p8tGHeFQzYv8UmSKUvnHtrsF25QjPjVibtMGqdexq9g/640?wx_fmt=png "")  
  
新的网络钓鱼攻击利用Windows 0 day 漏洞投放Qbot恶意软件，而不显示Web标记安全警告。  
  
当文件从互联网或电子邮件附件等不受信任的远程位置下载时，Windows会给文件添加一个名为“Web标记”（Mark of the Web）的特殊属性。  
  
这个Web标记（MoTW）是一个备用数据流，含有关于该文件的信息，比如表明文件来源的URL安全区域、引用者以及下载URL。  
  
当用户试图打开具有MoTW属性的文件时，Windows会显示安全警告，询问用户是否确定希望打开该文件。  
  
来自Windows的警告显示：“虽然来自互联网的文件可能很有用，但这种文件类型可能会对你的电脑造成潜在的危害。如果你不信任来源，请不要打开该软件。”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOUdYKibVQoC2qnGa6bmnrbBelTscohA6SBNsia8azE3qD8ssKPTicZh2EA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图1. Windows Web标记安全警告（来源：BleepingComputer）  
  
上个月惠普威胁情报团队报告，一起网络钓鱼攻击使用JavaScript文件分发Magniber勒索软件。  
  
这些JavaScript文件与网站上使用的那些文件不一样，而是扩展名为“.JS”的独立文件，可使用Windows脚本主机（wscript.exe）来执行。  
  
ANALYGENCE的高级漏洞分析师Will DormannD在分析这些文件后发现，威胁分子使用了一个新的Windows 0 day 漏洞，该漏洞阻止了Web标记安全警告的显示。  
  
想要利用该漏洞，可以使用base64编码的嵌入式签名块对JS文件（或其他类型的文件）进行签名，微软的这篇支持文章有详细描述（https://learn.microsoft.com/en-us/previous-versions/tn-archive/ee176795(v=technet.10)?redirectedfrom=MSDN）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOIrPlnpXkmnONoX4nicu2uNFUcwb6gTCCELk3TPPYBHdjbgw6M9h8k1w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图2. 用于安装Magniber勒索软件的JavaScript文件（来源：BleepingComputer）  
  
然而，当带有这种畸形签名的恶意文件被打开时，Windows自动允许该程序运行，而不是被微软SmartScreen标记出来、显示MoTW安全警告。  
  
**QBot恶意软件活动利用Windows 0 day 漏洞**  
  
最近的QBot恶意网络钓鱼活动已经分发了含有ISO镜像的由密码保护的ZIP压缩包。这些ISO镜像含有用于安装恶意软件的Windows快捷方式和DLL。  
  
ISO镜像被用来分发恶意软件，因为Windows没有正确地将“Web标记”传播到里面的文件中，从而允许含有的文件绕过Windows安全警告。  
  
作为微软2022年11月补丁的一部分，微软已发布了修复这个错误的安全更新，促使MoTW标记传播到打开的ISO镜像中的所有文件，从而修复了这个安全绕过漏洞。  
  
在安全研究人员ProxyLife发现的一起新的QBot网络钓鱼活动中，威胁分子通过分发带有畸形签名的JS文件，转而利用这个Windows Web标记 0 day 漏洞。  
  
这起新的网络钓鱼活动始于一封电子邮件，邮件中附有指向所谓文件的链接和文件的密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOW9X6ia0IrGMEibBibOJBicdOWKJibVu0yl2VuQyS7HljsfUfKmlSAiaArgTw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图3. 附有下载恶意压缩包的链接的网络钓鱼电子邮件（来源：BleepingComputer）  
  
点击链接后，会下载一个受密码保护的ZIP压缩包，压缩包含有另一个ZIP文件和一个IMG文件。  
  
在Windows 10及更新版本中，双击IMG或ISO等磁盘镜像文件后，操作系统会自动将其挂载为新的盘符。  
  
该IMG文件含有一个.js文件（‘WW.js’）、一个文本文件（‘data.txt’）和另一个文件夹，该文件夹含有一个重命名为.tmp文件（‘likeblence .tmp’）的DLL文件，如下所示。值得一提的是，文件名会随着每起活动而变，所以不应该被认为是静态的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOPTEVGdNGpVibcqnyeTgttQl5yso9aWz5eibfg1T7WKMNuEIo7HicCEic9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图4. 挂载的IMG文件（来源：BleepingComputer）  
  
该JS文件含有VB脚本，脚本会读取data.txt文件，这个文件含有‘vR32’字符串，并将内容附加到shellexecute命令的参数后面，以加载‘port/resemblance.tmp’DLL文件。在这封特定的邮件中，重构的命令如下：  
  
regSvR32 port\\resemblance.tmp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOibL3gibJ6JticJ69pR1RS1HBrQJOmtWrWBjVPh6u2q1zYvSPIJqibAThJA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图5. JS文件带有畸形签名，可以利用Windows  0 day 漏洞（来源：BleepingComputer）  
  
由于JS文件来自互联网，在Windows中启动它会显示Web标记安全警告。  
  
然而，从上面的JS脚本图像中可以看到，它使用Magniber勒索软件活动中使用的同一个畸形密钥来签名，以利用Windows 0 day 漏洞。  
  
这个畸形的签名允许JS脚本运行和加载QBot恶意软件，而不显示来自Windows的任何安全警告，如下面的启动进程所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29km3tpoharNf04cPdXlibrOYvkGAEBeXe09Hp2NiboDXh6JdjiawpQyuUuiaANObzzyjZr8bMP664WMg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图6. 启动QBot DLL的Regsvr32.exe（来源：BleepingComputer）  
  
经过一段短暂的时间后，恶意软件加载程序将把QBot DLL注入到合法的Windows进程中，以逃避检测，比如wermgr.exe或AtBroker.exe。  
  
微软从10月份以来就知道了这个 0 day 漏洞，鉴于其他恶意软件活动在利用该漏洞，但愿该漏洞会在2022年12月补丁安全更新中得到修复。  
  
**QBot恶意软件**  
  
QBot又叫Qakbot，是一种Windows恶意软件，最初只是一种银行木马，但已演变为恶意软件释放器。  
  
一旦加载，该恶意软件将在后台悄悄运行，同时窃取电子邮件用于其他网络钓鱼攻击或安装另外的攻击载荷，比如Brute Ratel、Cobalt Strike及其他恶意软件。  
  
安装Brute Ratel和Cobalt Strike后利用工具包通常会导致更具破坏性的攻击，比如数据盗窃和勒索软件攻击。  
  
在过去，Egregor和Prolock勒索软件团伙与QBot分发团伙狼狈为奸，伺机访问公司网络。最近，继QBot感染之后，网络上出现了Black Basta勒索软件攻击。  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/new-attacks-use-windows-security-bypass-zero-day-to-drop-malware/  
  
  
  
原文来源  
：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
