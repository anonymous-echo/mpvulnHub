#  RomCom 利用零日漏洞进行复杂的网络攻击 Firefox 和 Windows   
 信息安全大事件   2024-11-26 11:52  
  
被称为   
RomCom 的与俄罗斯结盟的威胁行为者与两个安全漏洞的零日利用有关，一个在 Mozilla Firefox 中，另一个在 Microsoft Windows 中，作为旨在向受害者系统提供同名后门的攻击的一部分。  
  
“在一次成功的攻击中，如果受害者浏览包含漏洞利用的网页，攻击者可以运行任意代码——不需要任何用户交互（零点击）——在这种情况下，这导致在受害者的计算机上安装了 RomCom 的后门，”ESET 在与 The Hacker News 分享的一份报告中说。  
  
有问题的漏洞如下：  
- CVE-2024-9680（CVSS 评分：9.8）- Firefox 动画组件中的释放后使用漏洞（Mozilla 于 2024 年 10 月修补）  
  
- CVE-2024-49039（CVSS 评分：8.8）- Windows Task Scheduler 中的权限提升漏洞（Microsoft 于 2024 年 11 月修补）  
  
RomCom，也被称为 Storm-0978、Tropical Scorpius、UAC-0180、UNC2596 和 Void Rabisu，至少自 2022 年以来就有进行网络犯罪和间谍活动的记录。  
  
这些攻击以部署   
RomCom RAT 而著称，这是一种积极维护的恶意软件，能够执行命令并将其他模块下载到受害者的机器上。  
  
斯洛伐克网络安全公司发现的攻击链涉及使用虚假网站（economistjournal[.]云）负责将潜在受害者重定向到服务器 （Redjournal[.]云）托管恶意负载，进而将这两个缺陷串在一起以实现代码执行并丢弃 RomCom RAT。  
  
目前尚不清楚指向虚假网站的链接是如何分发的，但已经发现，如果从易受攻击的   
Firefox 浏览器版本访问该网站，则会触发漏洞利用。  
  
“如果受害者使用易受攻击的浏览器访问提供此漏洞的网页，则会触发漏洞并在内容进程中执行 shellcode，”ESET 解释说。  
  
“shellcode 由两部分组成：第一部分从内存中检索第二部分并将包含的页面标记为可执行，而第二部分则基于开源项目 Shellcode Reflective DLL Injection （RDI） 实现 PE 加载程序。”  
  
结果是   
Firefox 的沙盒逃逸，最终导致在受感染的系统上下载和执行 RomCom RAT。这是通过嵌入式库（“PocLowIL”）实现的，该库旨在通过将 Windows 任务计划程序缺陷武器化来获得提升的权限，从而突破浏览器的沙盒内容进程。  
  
ESET 收集的遥测数据显示，访问漏洞利用托管站点的大多数受害者位于欧洲和北美。  
  
CVE-2024-49039 也是由 Google 的威胁分析小组 （TAG） 独立发现并向 Microsoft 报告的，这一事实表明，可能不止一个威胁行为者可能一直在将其作为零日漏洞进行利用。  
  
还值得注意的是，这是继   
2023 年 6 月通过 Microsoft Word 滥用 CVE-2023-36884 之后，RomCom 第二次被发现在野外利用零日漏洞。  
  
“将两个零日漏洞链接在一起，使 RomCom 获得了不需要用户交互的漏洞，”ESET 说。“这种复杂程度表明了威胁行为者获得或发展隐蔽能力的意愿和手段。”  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006371" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
