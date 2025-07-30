#  Moxa 问题修复 PT 交换机中的关键身份验证绕过漏洞   
 信息安全大事件   2025-03-11 20:03  
  
台湾公司   
Moxa 发布了一个安全更新，以解决影响其 PT 交换机的关键安全漏洞，该漏洞可能允许攻击者绕过身份验证保证。  
  
该漏洞被跟踪为   
CVE-2024-12297，CVSS v4 评分为 9.2 分（满分 10.0 分）。  
  
“由于授权机制存在缺陷，多个 Moxa PT 交换机容易受到身份验证绕过的影响，”该公司在上周发布的公告中表示。  
  
“尽管进行了客户端和后端服务器验证，但攻击者可以利用其实施中的弱点。此漏洞可能使暴力攻击能够猜测有效凭据，或使 MD5 冲突攻击能够伪造身份验证哈希，从而可能危及设备的安全性。  
  
换句话说，成功利用此缺点可能会导致身份验证绕过，并允许攻击者未经授权访问敏感配置或中断服务。  
  
该漏洞影响以下版本：  
- PT-508 系列（固件版本 3.8 及更早版本）  
  
- PT-510 系列（固件版本 3.8 及更早版本）  
  
- PT-7528 系列（固件版本 5.0 及更早版本）  
  
- PT-7728 系列（固件版本 3.9 及更早版本）  
  
- PT-7828 系列（固件版本 4.0 及更早版本）  
  
- PT-G503 系列（固件版本 5.3 及更早版本）  
  
- PT-G510 系列（固件版本 6.5 及更早版本）  
  
- PT-G7728 系列（固件版本 6.5 及更早版本）  
  
- PT-G7828 系列（固件版本 6.5 及更早版本）  
  
联系   
Moxa 技术支持团队获取漏洞补丁。该公司感谢总部位于莫斯科的 Rosatom 自动控制系统 （RASU） 的 Artem Turyshev 报告了该漏洞。  
  
除了应用最新修复程序之外，建议使用受影响产品的公司使用防火墙或访问控制列表   
（ACL） 限制网络访问、实施网络分段、最大限度地减少直接暴露于 Internet、实施多重身份验证 （MFA） 以访问关键系统、启用事件日志记录，并监控网络流量和设备行为是否存在异常活动。  
  
值得注意的是，Moxa 早在 2025 年 1 月中旬就解决了运行固件版本 3.11 及更早版本的以太网交换机 EDS-508A 系列中的相同漏洞。  
  
在两个多月前，Moxa 针对影响其蜂窝路由器、安全路由器和网络安全设备的两个安全漏洞（CVE-2024-9138 和 CVE-2024-9140）推出了补丁，这些漏洞可能允许权限提升和命令执行。  
  
上个月，它还解决了影响各种交换机的多个高严重性缺陷（CVE-2024-7695、CVE-2024-9404 和 CVE-2024-9137），这些缺陷可能导致拒绝服务 （DoS） 攻击或命令执行。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__26" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__27" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br data-filtered="filtered" style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br data-filtered="filtered" style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br data-filtered="filtered" style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br data-filtered="filtered" style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img alt="图片" class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006618" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br data-filtered="filtered" style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
