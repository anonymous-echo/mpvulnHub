#  GFI KerioControl 中的严重 RCE 缺陷允许通过 CRLF 注入远程执行代码   
 信息安全大事件   2025-01-09 20:20  
  
威胁行为者正试图利用最近披露的威胁   
GFI KerioControl 防火墙的安全漏洞，如果成功利用该漏洞，可能会允许恶意行为者实现远程代码执行 （RCE）。  
  
有问题的漏洞   
CVE-2024-52875 是指回车换行 （CRLF） 注入攻击，为 HTTP 响应拆分铺平了道路，这可能导致跨站点脚本 （XSS） 缺陷。  
  
成功利用一键式   
RCE 缺陷，攻击者可以通过引入回车符 （\r） 和换行符 （\n） 将恶意输入注入 HTTP 响应标头。  
  
据安全研究员   
Egidio Romano 称，该漏洞影响了 KerioControl 9.2.5 至 9.4.5 版本，他于 2024 年 11 月初发现并报告了该漏洞。  
  
在以下   
URI 路径中发现了 HTTP 响应拆分缺陷：  
- /nonauth/addCertException.cs  
  
- /nonauth/guestConfirm.cs  
  
- /nonauth/expiration.cs  
  
“通过'dest'GET 参数传递给这些页面的用户输入在用于在 302 HTTP 响应中生成'Location'HTTP 标头之前没有经过适当的清理，”Romano 说。  
  
“具体来说，该应用程序无法正确过滤/删除换行符 （LF） 字符。这可以被用来执行 HTTP 响应拆分攻击，这反过来又可能允许它执行反射跨站点脚本 （XSS） 和可能的其他攻击。  
  
GFI 于 2024 年 12 月 19 日发布了该漏洞的修复程序，版本为 9.4.5 补丁 1。此后，概念验证 （PoC） 漏洞已经可用。  
  
具体来说，攻击者可以制作一个恶意   
URL，以便管理员用户单击该 URL 会触发攻击者控制的服务器上托管的 PoC 的执行，然后该服务器通过固件升级功能上传恶意 .img 文件，授予对防火墙的 root 访问权限。  
  
威胁情报公司   
GreyNoise 报告称，针对 CVE-2024-52875 的利用尝试始于 2024 年 12 月 28 日，迄今为止，攻击源自新加坡和香港的 7 个唯一 IP 地址。  
  
根据   
Censys 的数据，有超过 23800 个公开的 GFI KerioControl 实例。这些服务器中的大多数位于伊朗、乌兹别克斯坦、意大利、德国、美国、捷克、白俄罗斯、乌克兰、俄罗斯和巴西。  
  
目前尚不清楚利用该漏洞的攻击的确切性质。建议   
KerioControl 的用户尽快采取措施保护他们的实例，以减轻潜在威胁。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006525" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
