#  网络犯罪分子使用 Excel 漏洞来传播无文件 Remcos RAT 恶意软件   
 信息安全大事件   2024-11-11 20:17  
  
网络安全研究人员发现了一种新的网络钓鱼活动，该活动传播了一种名为  
Remcos RAT  
 的已知商业恶意软件的新无文件变体。  
  
Remcos RAT“为购买提供广泛的高级功能，以远程控制属于买家的计算机，”Fortinet FortiGuard Labs 研究员 Xiaopeng Zhang 在上周发表的分析  
中说  
。  
  
“然而，威胁行为者滥用 Remcos 从受害者那里收集敏感信息，并远程控制他们的计算机以执行进一步的恶意行为。”  
  
攻击的起点是网络钓鱼电子邮件，它使用以采购订单为主题的诱饵来诱骗收件人打开   
Microsoft Excel 附件。  
  
恶意 Excel 文档旨在利用 Office 中的已知远程代码执行缺陷（  
CVE-2017-0199，CVSS  
 评分：7.8）从远程服务器下载 HTML 应用程序 （HTA） 文件（“cookienetbookinetcahce.hta”）（“192.3.220[.]22“） 并使用 mshta.exe 启动它。  
  
就其本身而言，HTA 文件包装在多层 JavaScript、Visual Basic Script 和 PowerShell 代码中，以逃避检测。它的主要职责是从同一服务器检索可执行文件并执行它。  
  
二进制文件随后继续运行另一个经过混淆处理的   
PowerShell 程序，同时还采用了一系列反分析和反调试技术，使检测工作复杂化。在下一步中，恶意代码利用进程挖空最终下载并运行 Remcos RAT。  
  
“它不是将 Remcos 文件保存到本地文件中并运行它，而是直接在当前进程的内存中部署 Remcos，”Zhang 说。“换句话说，它是 Remcos 的无文件变体。”  
  
Remcos RAT 能够从受感染的主机中收集各种信息，包括系统元数据，并可以执行攻击者通过命令和控制 （C2） 服务器远程发出的指令。  
  
这些命令允许程序收集文件、枚举和终止进程、管理系统服务、编辑   
Windows 注册表、执行命令和脚本、捕获剪贴板内容、更改受害者的桌面壁纸、启用摄像头和麦克风、下载额外的有效负载、录制屏幕，甚至禁用键盘或鼠标输入。  
  
披露之际，Wallarm 透露，威胁行为者正在  
滥用 Docusign API  
 发送看似真实的假发票，以试图欺骗毫无戒心的用户并大规模进行网络钓鱼活动。  
  
该攻击需要创建一个合法的付费   
Docusign 帐户，使攻击者能够更改模板并直接使用 API。然后，这些帐户用于创建特制的发票模板，模拟对 Norton Antivirus 等知名品牌的文档进行电子签名的请求。  
  
该公司  
表示  
：“与依赖于欺骗性电子邮件和恶意链接的传统网络钓鱼诈骗不同，这些事件使用真实的 DocuSign 帐户和模板来冒充信誉良好的公司，让用户和安全工具措手不及。  
  
“如果用户对此文档进行电子签名，攻击者可以使用签名文档向 DocuSign 以外的组织请求付款，或通过 DocuSign 将签名文档发送给财务部门进行付款。”  
  
还观察到网络钓鱼活动利用一种称为   
ZIP 文件串联的非常规策略来绕过安全工具并将远程访问木马分发给目标。  
  
该方法涉及将多个   
ZIP 存档附加到一个文件中，由于 7-Zip、WinRAR 和 Windows 文件资源管理器等不同程序解压缩和解析此类文件的差异，这引入了安全问题，从而导致恶意负载被忽略的情况。  
  
“通过利用 ZIP 阅读器和存档管理器处理串联 ZIP 文件的不同方式，攻击者可以嵌入专门针对某些工具用户的恶意软件，”Perception Point 在最近的一份报告中  
指出  
。  
  
“威胁行为者知道这些工具通常会遗漏或忽视隐藏在串联档案中的恶意内容，从而使他们能够在不被发现的情况下传递其有效载荷，并针对使用特定程序处理档案的用户。”  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__14" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__15" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006307" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
