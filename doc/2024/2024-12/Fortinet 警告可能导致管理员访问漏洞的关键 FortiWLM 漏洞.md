#  Fortinet 警告可能导致管理员访问漏洞的关键 FortiWLM 漏洞   
 信息安全大事件   2024-12-19 12:00  
  
Fortinet 针对影响 Wireless LAN Manager （FortiWLM） 的现已修补的关键安全漏洞发布了公告，该漏洞可能导致敏感信息泄露。  
  
该漏洞被跟踪为   
CVE-2023-34990，CVSS 评分为 9.6 分（满分 10.0 分）。  
  
“FortiWLM 中的相对路径遍历 [CWE-23] 可能允许未经身份验证的远程攻击者读取敏感文件，”该公司在周三发布的警报中表示。  
  
但是，根据   
NIST 国家漏洞数据库 （NVD） 中对安全漏洞的描述，攻击者也可以利用路径遍历漏洞“通过特制的 Web 请求执行未经授权的代码或命令”。  
  
该漏洞会影响该产品的以下版本 :  
- FortiWLM 版本 8.6.0 至 8.6.5（已在 8.6.6 或更高版本中修复）  
  
- FortiWLM 版本 8.5.0 至 8.5.4（已在 8.5.5 或更高版本中修复）  
  
该公司感谢   
Horizon3.ai 安全研究员 Zach Hanley 发现并报告了该缺陷。值得一提的是，CVE-2023-34990 指的是网络安全公司在 3 月份披露的“未经身份验证的有限文件读取漏洞”，是 FortiWLM 中更广泛的六大缺陷的一部分。  
  
“此漏洞允许未经身份验证的远程攻击者访问和滥用内置功能，这些功能旨在通过对 /ems/cgi-bin/ezrf_lighttpd.cgi 端点的精心设计的请求来读取系统上的特定日志文件，”Hanley 当时说。  
  
“此问题是由于请求参数缺乏输入验证导致攻击者能够遍历目录并读取系统上的任何日志文件。”  
  
成功利用   
CVE-2023-34990 可能允许威胁行为者读取 FortiWLM 日志文件并获取用户的会话 ID 和登录，从而允许他们利用经过身份验证的端点。  
  
更糟糕的是，攻击者可以利用   
Web 会话 ID 在用户会话之间是静态的事实来劫持它们并获得对设备的管理权限。  
  
这还不是全部。攻击者还可以将   
CVE-2023-34990 与 CVE-2023-48782（CVSS 评分：8.8）相结合，这是一个经过身份验证的命令注入漏洞，也已在 FortiWLM 8.6.6 中修复，以在 root 上下文中获得远程代码执行。  
  
Fortinet 还修补了 FortiManager 中的一个高严重性操作系统命令注入漏洞，该漏洞可能允许经过身份验证的远程攻击者通过 FGFM 构建的请求执行未经授权的代码。  
  
漏洞（CVE-2024-48889，CVSS 评分：7.2）已在以下版本中得到解决 :  
- FortiManager 7.6.0 （已在 7.6.1 或以上版本修复）  
  
- FortiManager 版本 7.4.0 至 7.4.4（已在 7.4.5 或更高版本中修复）  
  
- FortiManager Cloud 版本 7.4.1 至 7.4.4（已在 7.4.5 或更高版本中修复）  
  
- FortiManager 版本 7.2.3 至 7.2.7（已在 7.2.8 或更高版本中修复）  
  
- FortiManager Cloud 版本 7.2.1 至 7.2.7（已在 7.2.8 或更高版本中修复）  
  
- FortiManager 版本 7.0.5 至 7.0.12（已在 7.0.13 或更高版本中修复）  
  
- FortiManager Cloud 版本 7.0.1 至 7.0.12（已在 7.0.13 或更高版本中修复）  
  
- FortiManager 版本 6.4.10 至 6.4.14（已在 6.4.15 或更高版本中修复）  
  
Fortinet 还指出，如果启用“fmg-status”，许多旧型号（1000E、1000F、2000E、3000E、3000F、3000G、3500E、3500F、3500G、3700F、3700G 和 3900E）都会受到 CVE-2024-48889 的影响。  
  
随着   
Fortinet 设备成为威胁行为者的攻击磁铁，用户必须使其实例保持最新状态以防范潜在威胁。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006468" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;retryload=2&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
