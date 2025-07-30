#  Microsoft 修复了导致 Microsoft 365 Copilot 数据被盗的 ASCII 走私漏洞   
 信息安全大事件   2024-08-27 20:23  
  
有关   
Microsoft 365 Copilot 中现已修补的漏洞的详细信息已经出现，该漏洞可能使用一种称为 ASCII 走私的技术来窃取敏感的用户信息。  
  
“ASCII 走私是一种新技术，它使用特殊的 Unicode 字符来镜像 ASCII，但实际上在用户界面中不可见，”安全研究员 Johann Rehberger 说。  
  
“这意味着攻击者可以让 [大型语言模型] 向用户呈现不可见数据，并将其嵌入到可点击的超链接中。这种技术基本上是暂存数据以进行泄露！  
  
整个攻击将许多攻击方法串联在一起，将它们塑造成一个可靠的漏洞利用链。这包括以下步骤：  
- 通过隐藏在聊天中共享的文档中的恶意内容触发提示注入  
  
- 使用提示注入有效负载指示   
Copilot 搜索更多电子邮件和文档  
  
- 利用   
ASCII 走私诱使用户点击链接，将有价值的数据泄露到第三方服务器  
  
攻击的最终结果是电子邮件中存在的敏感数据，包括多因素身份验证   
（MFA） 代码，可能会传输到对手控制的服务器。此后，Microsoft 在 2024 年 1 月进行了负责任的披露后解决了这些问题。  
  
这一发展是在针对   
Microsoft 的 Copilot 系统的概念验证 （PoC） 攻击被证明以操纵响应、泄露私人数据和躲避安全保护之际发生的，再次凸显了监控人工智能 （AI） 工具中风险的必要性。  
  
Zenity 详细介绍了这些方法，允许恶意行为者执行检索增强生成 （RAG） 中毒和间接提示注入，从而导致远程代码执行攻击，从而完全控制 Microsoft Copilot 和其他 AI 应用程序。在假设的攻击场景中，具有代码执行能力的外部黑客可以诱骗 Copilot 为用户提供网络钓鱼页面。  
  
也许最新颖的攻击之一是能够将   
AI 变成鱼叉式网络钓鱼机器。这种被称为 LOLCopilot 的红队技术允许有权访问受害者电子邮件帐户的攻击者发送模仿受感染用户风格的网络钓鱼消息。  
  
Microsoft 还承认，使用 Microsoft Copilot Studio 创建且缺乏任何身份验证保护的公开暴露的 Copilot 机器人可能是威胁行为者提取敏感信息的途径，前提是他们事先知道 Copilot 名称或 URL。  
  
Rehberger 说：“企业应评估其风险承受能力和风险敞口，以防止 Copilots（以前称为 Power Virtual Agents）的数据泄露，并相应地启用数据丢失防护和其他安全控制措施，以控制 Copilot 的创建和发布。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006026" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
  
  
  
  
