#  APT-C-60 Group 利用 WPS Office 漏洞部署 SpyGlace 后门   
 信息安全大事件   2024-08-29 20:30  
  
与韩国结盟的网络间谍活动与零日利用金山   
WPS Office 中现已修补的关键远程代码执行漏洞以部署名为 SpyGlace 的定制后门有关。  
  
据网络安全公司   
ESET 和 DBAPPSecurity 称，该活动被归因于一个名为 APT-C-60 的威胁行为者。已发现这些攻击会用恶意软件感染中国和东亚用户。  
  
有问题的安全漏洞是   
CVE-2024-7262（CVSS 分数：9.3），这是由于缺乏对用户提供的文件路径的正确验证。这个漏洞本质上允许对手上传任意 Windows 库并实现远程代码执行。  
  
ESET 表示，该错误“允许通过劫持 WPS Office 插件组件的控制流来执行代码promecefpluginhost.exe”，并补充说它找到了另一种实现相同效果的方法。第二个漏洞被跟踪为 CVE-2024-7263 （CVSS 评分：9.3）。  
  
APT-C-60 构思的攻击将漏洞武器化为一键式漏洞利用，该漏洞采用 2024 年 2 月上传到 VirusTotal 的诱杀电子表格文档的形式。  
  
具体来说，该文件嵌入了一个恶意链接，单击该链接时，会触发多阶段感染序列以传递   
SpyGlace 木马，这是一个名为 TaskControler.dll 的 DLL 文件，具有文件窃取、插件加载和命令执行功能。  
  
“漏洞利用开发人员在电子表格中嵌入了电子表格行和列的图片，以欺骗并说服用户该文档是常规电子表格，”安全研究员 Romain Dumont 说。“恶意超链接链接到图像，因此单击图片中的单元格会触发漏洞利用。”  
  
据总部位于北京的网络安全供应商   
ThreatBook 称，APT-C-60 据信自 2021 年以来一直活跃，早在 2022 年 6 月就在野外检测到 SpyGlace。  
  
Dumont 说：“无论该组织是开发还是购买了 CVE-2024-7262 漏洞，它肯定需要对应用程序的内部进行一些研究，但也需要了解 Windows 加载过程的行为方式。  
  
“这个漏洞很狡猾，因为它具有足够的欺骗性，可以诱骗任何用户点击看起来合法的电子表格，同时也非常有效和可靠。MHTML 文件格式的选择使攻击者能够将代码执行漏洞转化为远程漏洞。  
  
这家斯洛伐克网络安全公司指出，名为   
ScreenShareOTR（或 ss-otr）的 Pidgin 消息传递应用程序的恶意第三方插件包含负责从命令和控制 （C&C） 服务器下载下一阶段二进制文件的代码，最终导致部署 DarkGate 恶意软件。  
  
“正如宣传的那样，该插件的功能包括使用安全的不记录消息 （OTR） 协议的屏幕共享。但是，除此之外，该插件还包含恶意代码，“ESET 说。“具体来说，某些版本的 pidgin-screenshare.dll 可以从 C&C 服务器下载并执行 PowerShell 脚本。”  
  
该插件还包含键盘记录器和屏幕截图捕获功能，此后已从第三方插件列表中删除。建议已安装该插件的用户立即将其删除。  
  
此后，ESET 发现，在一个名为 Cradle 的应用程序（“cradle[.]im“） 的 Git，它声称是 Signal 消息应用程序的开源分支。该应用程序从 2023 年 9 月起可供下载近一年。  
  
通过运行   
PowerShell 脚本下载恶意代码，然后该脚本获取并执行编译后的 AutoIt 脚本，最终安装 DarkGate。Linux 风格的 Cradle 提供了一个 ELF 可执行文件，用于下载和执行 shell 命令，并将结果发送到远程服务器。  
  
另一个常见指标是插件安装程序和   
Cradle 应用程序都使用颁发给一家名为“INTERREX - SP. Z O.O.”的波兰公司颁发的有效数字证书进行签名，这表明肇事者正在使用不同的方法来传播恶意软件。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006038" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
  
