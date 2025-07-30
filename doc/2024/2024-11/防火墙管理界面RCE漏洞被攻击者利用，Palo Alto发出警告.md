#  防火墙管理界面RCE漏洞被攻击者利用，Palo Alto发出警告   
 信息安全大事件   2024-11-19 11:53  
  
近期网安巨头Palo Alto Networks发布安全警告，关于其防火墙产品管理界面中关键的远程命令执行（RCE）漏洞被利用。  
  
这个缺陷允许未经认证的攻击者在受影响的系统上执行任意命令，在有限的案例中观察到，这些防火墙管理界面暴露于互联网。  
  
该公司已将漏洞的严重性提升至关键级别，CVSSv4.0基础得分为9.3。这提示未遵循建议的安全实践的组织面临的高风险。  
  
Palo Alto Networks正在积极调查此问题，并已确认威胁行为者已经开始在野外利用这个漏洞。  
  
该漏洞主要影响可以从互联网访问的防火墙管理界面。Palo Alto Networks强烈建议客户立即检查其防火墙配置，并确保根据最佳实践指南，只有受信任的内部IP地址才能访问这些管理界面。  
  
公司强调，Prisma Access和Cloud NGFW 服务不受此漏洞影响，这减少了使用这些产品的用户的担忧。然而，对于其他防火墙系统，Palo Alto Networks警告说，如果无法保护管理接口，可能会使它们容易受到攻击。  
  
“目前，我们认为那些未按照我们推荐的部署最佳实践指南进行管理界面访问保护的设备面临更高的风险，”公司在其公告中表示。  
  
为了帮助客户识别可能易受攻击的设备，Palo Alto Networks通过其客户支持门户提供了指导。用户可以按照以下步骤操作：  
- 访问客户支持门户的Assets部分。  
  
- 查找标记有PAN-SA-2024-0015的设备，这些设备面向Internet的管理界面。  
  
如果没有列出这样的设备，这意味着Palo Alto的扫描未检测到该账户的任何公开接口。客户被敦促手动双重检查他们的配置。  
  
尽管在有限的案例中观察到活跃的利用，Palo Alto Networks尚未提供具体的入侵指标（IoC）。**建议客户监控异常活动，例如无法识别的配置更改或不熟悉的用户登录。**  
  
作为其持续响应的一部分，Palo Alto Networks正在准备补丁和威胁预防签名以缓解这个漏洞。这些修复预计将很快发布。  
  
与此同时，保护对防火墙管理界面的访问仍然是最有效的防御措施。公司将继续更新其公告，以获取新信息。  
  
对于持续的更新和通知，客户可以通过其支持门户订阅Palo Alto Networks的安全RSS源或电子邮件警报。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006336" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
