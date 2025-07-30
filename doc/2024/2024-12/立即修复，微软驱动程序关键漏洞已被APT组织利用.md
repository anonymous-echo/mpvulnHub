#  立即修复，微软驱动程序关键漏洞已被APT组织利用   
 信息安全大事件   2024-12-05 12:24  
  
近日，微软被曝Windows AFD.sys漏洞（编号：CVE-2024-38193）正在被黑客组织利用。该漏洞被归类为自带易受攻击驱动程序（BYOVD）漏洞，可影响Windows套接字的注册I/O（RIO）扩展，并允许攻击者远程接管整个系  
统。  
  
漏洞影响版本包括Windows 11（ARM64、x64，多个版本）、Windows 10（ARM64、x64、32位，多个版本）、Windows Server 2008、2012、2016、2019、2022（多个版本）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA68e4Im4fcAC2kjCm7oa3TML8VpxicbLr3DWWlo5CzhbecVicGRzXiaUOHaSFYgVTpom9EOf5GFlzgvQ/640?wx_fmt=png&from=appmsg "")  
  
目前，已有迹象表明黑客组织正在利用该漏洞发起攻击，例如朝鲜黑客组织Lazarus就是其中之一，其安装名为FUDModule的根工具包（rootkit），可在目标系统上获得最高权限。2024年8月，微软发布安全更新已经修复该漏洞，强烈建议组织及时进行修复。  
  
**漏洞概述**  
  
**漏洞成因**  
  
CVE-2024-38193漏洞存在于Windows辅助功能驱动程序（AFD.sys）中。AFD.sys是Winsock协议栈的关键组件之一，处理底层网络调用，并在内核模式下执行操作。漏洞的根本原因是AFD.sys在处理特定系统调用时缺乏适当的边界检查，导致攻击者可以构造恶意输入，触发内存溢出或其他未定义行为，从而绕过安全检查，提升权限。由于AFD.sys在所有Windows系统中广泛部署，这使得该漏洞特别危险。  
  
**漏洞利用过程**  
  
**漏洞触发**  
  
攻击者首先通过恶意应用程序或远程代码执行方式，向AFD.sys驱动程序发送恶意构造的系统调用请求。通过精心构造的输入，攻击者可以让AFD.sys在内核模式下执行越权操作。  
  
这种攻击方式利用了Windows内核的漏洞，能够在用户态和内核态之间绕过安全边界，执行未授权的操作。  
  
**权限提升**  
  
一旦漏洞触发，攻击者可以利用漏洞执行任意代码，并获得SYSTEM权限。通过这种方式，攻击者能够完全控制受影响的设备，部署恶意软件或修改系统配置。获得SYSTEM权限后，攻击者可以执行一系列高级操作，包括禁用安全软件、修改系统文件和执行其他恶意活动。  
  
**FUDModule根工具包的安装**  
  
获得SYSTEM权限后，攻击者会安装FUDModule根工具包。FUDModule是一种专门设计用于隐藏攻击痕迹、绕过安全监控的复杂恶意软件。通过关闭Windows的监控功能，FUDModule可以让攻击者在受害者系统中保持长期隐蔽。FUDModule的存在使得攻击者能够在不被发现的情况下持续控制目标系统，增加了防御的难度。  
  
**修复建议**  
  
微软已经发布了针对CVE-2024-38193的安全补丁，覆盖了多个Windows版本。建议所有用户和组织尽快应用补丁，避免系统遭到利用。及时应用补丁是防止漏洞利用的最有效手段之一，用户应确保系统和应用程序都安装了最新的安全更新。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__4" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__5" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006417" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
